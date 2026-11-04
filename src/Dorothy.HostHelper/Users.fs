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
open System.Text.RegularExpressions
open System.Numerics
open Microsoft.Win32.SafeHandles

module Users =
    type BackendError(message: string) =
        inherit InvalidOperationException(message)

    [<Struct; StructLayout(LayoutKind.Sequential, Size = 256)>]
    type private UsersStatx =
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

    [<DllImport("libc", EntryPoint = "statx", SetLastError = true)>]
    extern int private nativeStatx (int directoryFileDescriptor, string path, int flags, uint32 mask, UsersStatx& result)

    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int private nativeOpen (string path, int flags, int mode)

    [<DllImport("libc", EntryPoint = "openat", SetLastError = true)>]
    extern int private nativeOpenAt (int directoryFileDescriptor, string path, int flags, int mode)

    [<DllImport("libc", EntryPoint = "mkdirat", SetLastError = true)>]
    extern int private nativeMkdirAt (int directoryFileDescriptor, string path, int mode)

    [<DllImport("libc", EntryPoint = "fchmod", SetLastError = true)>]
    extern int private nativeFchmod (int fileDescriptor, int mode)

    [<DllImport("libc", EntryPoint = "fchown", SetLastError = true)>]
    extern int private nativeFchown (int fileDescriptor, uint32 owner, uint32 group)

    [<DllImport("libc", EntryPoint = "renameat", SetLastError = true)>]
    extern int private nativeRenameAt (int oldDirectoryFileDescriptor, string oldPath, int newDirectoryFileDescriptor, string newPath)

    [<DllImport("libc", EntryPoint = "unlinkat", SetLastError = true)>]
    extern int private nativeUnlinkAt (int directoryFileDescriptor, string path, int flags)

    [<DllImport("libc", EntryPoint = "fsync", SetLastError = true)>]
    extern int private nativeFsync (int fileDescriptor)

    [<DllImport("libc", EntryPoint = "close", SetLastError = true)>]
    extern int private nativeClose (int fileDescriptor)

    [<DllImport("libc", EntryPoint = "geteuid")>]
    extern uint32 private nativeGetEffectiveUserId ()

    [<DllImport("libc", EntryPoint = "getegid")>]
    extern uint32 private nativeGetEffectiveGroupId ()

    [<DllImport("libc", EntryPoint = "write", SetLastError = true)>]
    extern nativeint private nativeWrite (int fileDescriptor, byte[] buffer, unativeint count)

    type private FileMetadata =
        { FileType: int
          Mode: int
          UserId: uint32
          GroupId: uint32
          LinkCount: uint32
          Inode: uint64
          DeviceMajor: uint32
          DeviceMinor: uint32
          Size: uint64 }

    type private GroupAccount =
        { Name: string
          Gid: int
          Members: Set<string> }

    type private UserAccount =
        { Name: string
          Uid: int
          Gid: int
          Description: string
          Home: string
          Shell: string }

    type private ShadowAccount =
        { Name: string
          PasswordHash: string
          MinimumDays: int option
          MaximumDays: int option
          WarningDays: int option
          InactiveDays: int option
          ExpiryDay: int64 option }

    type private LocalState =
        { Users: Map<string, UserAccount>
          Groups: Map<string, GroupAccount>
          Shadows: Map<string, ShadowAccount> }

    type private IdRange =
        { Start: uint32
          Count: uint32 }

    type private GroupSpec =
        { Name: string
          Gid: int option
          Kind: string option
          Existing: string
          State: string }

    type private HomeSpec =
        { Kind: string
          Path: string option
          Mode: int option
          Skeleton: string option }

    type private PasswordSpec =
        { Kind: string
          Hash: string option
          Update: string }

    type private KeySpec =
        { Id: string
          KeyType: string
          KeyData: string
          Comment: string option
          Restrict: bool
          AllowPty: bool option
          AllowAgentForwarding: bool option
          AllowPortForwarding: bool option
          AllowX11Forwarding: bool option
          AllowUserRc: bool option
          AllowFrom: string list
          Command: string option
          Expires: DateTimeOffset option
          PermitOpen: string list
          PermitListen: string list
          VerifyRequired: bool }

    type private KeySet =
        { Mode: string
          Keys: KeySpec list }

    type private UserSpec =
        { Name: string
          State: string
          Kind: string option
          Existing: string
          Uid: int option
          Description: string option
          PrimaryGroup: (string * string option) option
          SupplementaryGroups: (string * string list) option
          Home: HomeSpec option
          Shell: string option
          Password: PasswordSpec option
          Expiry: (string * string option) option
          PasswordPolicy: Map<string, int>
          SubordinateUids: IdRange list option
          SubordinateGids: IdRange list option
          OnDelete: string option
          AuthorizedKeys: KeySet option }

    type private UserOwnership =
        { Uid: int
          Gid: int
          Identity: string
          CreationComplete: bool
          CreationHomeKind: string option
          CreationHomePath: string option
          CreationHomeMode: int option
          CreationHomeSkeleton: string option
          CreationShell: string option
          MembershipsAdded: Set<string>
          KeyMode: string option
          KeyHome: string option
          KeyLines: string list
          KeyPendingBefore: string list option
          KeyPendingAfter: string list option
          KeyPendingDesired: string list option
          KeyPendingMode: string option
          KeyPendingHome: string option
          KeyPendingAdded: Set<string>
          KeysAdded: Set<string>
          SubordinateUidsAdded: Set<IdRange>
          SubordinateGidsAdded: Set<IdRange>
          PasswordKind: string option
          PasswordDigest: string option }

    type private GroupOwnership =
        { Gid: int
          Identity: string
          Kind: string option }

    type private Journal =
        { OwnerId: string
          Groups: Map<string, GroupOwnership>
          Users: Map<string, UserOwnership> }

    type private IdBounds =
        { UserMinimum: int
          UserMaximum: int
          SystemUserMinimum: int
          SystemUserMaximum: int
          GroupMinimum: int
          GroupMaximum: int
          SystemGroupMinimum: int
          SystemGroupMaximum: int
          UserGroupsEnabled: bool
          ReservedUserIds: Set<int>
          ReservedGroupIds: Set<int> }

    type private Request =
        { Operation: string
          ResourceId: string
          ConnectionUser: string
          Groups: GroupSpec list
          Users: UserSpec list }

    let private fail (message: string) = raise (BackendError(message))

    let private hasControl (value: string) =
        value |> Seq.exists (fun character -> int character < 32 || int character = 127)

    let private validName = Regex("\\A[a-z_][a-z0-9_-]{0,31}\\z", RegexOptions.CultureInvariant)
    let private validKeyId = Regex("\\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\\z", RegexOptions.CultureInvariant)
    let private forwardEndpointPattern = Regex("\\A(?:[A-Za-z0-9._-]+@)?(?:\\*|[A-Za-z0-9._-]+|\\[[0-9A-Fa-f:.]+\\]):(?:\\*|[0-9]{1,5})\\z", RegexOptions.CultureInvariant)
    let private strictUtf8 = UTF8Encoding(false, true)
    let private directoryType = 0x4000
    let private regularType = 0x8000
    let private openDirectoryFlags = 0x10000 ||| 0x80000 ||| 0x20000
    let private openReadOnlyFlags = 0x80000 ||| 0x20000 ||| 0x800
    let private openWriteFlags = 0x1 ||| 0x40 ||| 0x80 ||| 0x80000 ||| 0x20000
    let private atSymlinkNoFollow = 0x100
    let private atEmptyPath = 0x1000
    let private ownerDirectory = "/var/lib/keroosha-iac/users"
    let private maximumJournalBytes = 4 * 1024 * 1024
    let private maximumAuthorizedKeysBytes = 1024 * 1024

    let private isProductionRoot (environment: HostEnvironment) =
        Path.GetFullPath(environment.Root) = Path.DirectorySeparatorChar.ToString()

    let private actualPath (environment: HostEnvironment) (logicalPath: string) : string = HostEnvironment.path environment logicalPath

    let private effectiveOwner (environment: HostEnvironment) : uint32 =
        if isProductionRoot environment then 0u else
            let mutable metadata = Unchecked.defaultof<UsersStatx>
            let rootPath = actualPath environment "/"
            if nativeStatx(-100, rootPath, atSymlinkNoFollow, 0x7FFu, &metadata) <> 0 then
                fail "cannot inspect the mapped host root"
            metadata.UserId

    let private metadataFromStat (stat: UsersStatx) : FileMetadata =
        { FileType = int (stat.Mode &&& 0xF000us)
          Mode = int (stat.Mode &&& 0x0FFFus)
          UserId = stat.UserId
          GroupId = stat.GroupId
          Inode = stat.Inode
          DeviceMajor = stat.DeviceMajor
          DeviceMinor = stat.DeviceMinor
          LinkCount = stat.LinkCount
          Size = stat.Size }

    let rec private inspectAt (directoryFileDescriptor: int) (path: string) : FileMetadata option =
        let mutable stat = Unchecked.defaultof<UsersStatx>
        if nativeStatx(directoryFileDescriptor, path, atSymlinkNoFollow, 0x7FFu, &stat) = 0 then
            Some(metadataFromStat stat)
        else
            let errorCode = Marshal.GetLastPInvokeError()
            if errorCode = 2 then None
            elif errorCode = 4 then inspectAt directoryFileDescriptor path
            else fail "cannot safely inspect a host filesystem path"

    let private inspectPath (path: string) : FileMetadata option = inspectAt -100 path

    let private inspectDescriptor (fileDescriptor: int) : FileMetadata =
        let mutable stat = Unchecked.defaultof<UsersStatx>
        if nativeStatx(fileDescriptor, "", atEmptyPath, 0x7FFu, &stat) <> 0 then
            fail "cannot inspect an open host filesystem object"
        metadataFromStat stat

    let private openRootDirectory (environment: HostEnvironment) : SafeFileHandle =
        let rootPath = actualPath environment "/"
        let descriptor = nativeOpen(rootPath, openDirectoryFlags, 0)
        if descriptor < 0 then fail "cannot safely open the mapped host root"
        new SafeFileHandle(nativeint descriptor, true)

    let private validateDirectoryMetadata (environment: HostEnvironment) (allowWritable: bool) (metadata: FileMetadata) : unit =
        if metadata.FileType <> directoryType then fail "a required host path is not a real directory"
        let owner = effectiveOwner environment
        if metadata.UserId <> owner then fail "a host directory has an unexpected owner"
        if not allowWritable && (metadata.Mode &&& 0o022) <> 0 then fail "a host directory is group- or world-writable"

    let private splitLogicalPath (logicalPath: string) =
        if String.IsNullOrWhiteSpace logicalPath || not (Path.IsPathRooted logicalPath) || hasControl logicalPath then
            fail "host paths must be absolute and contain no control characters"
        let normalized =
            try Path.GetFullPath logicalPath
            with _ -> fail "host path is invalid"
        if normalized <> logicalPath then fail "host paths must be canonical absolute paths"
        let components = logicalPath.TrimStart([| Path.DirectorySeparatorChar; Path.AltDirectorySeparatorChar |]).Split([| Path.DirectorySeparatorChar; Path.AltDirectorySeparatorChar |], StringSplitOptions.RemoveEmptyEntries)
        if components |> Array.exists (fun pathSegment -> pathSegment = "." || pathSegment = "..") then fail "host path contains an unsafe component"
        components

    let private openDirectoryChain (environment: HostEnvironment) (logicalPath: string) (createDirectories: bool) (finalMode: int) (finalOwner: uint32 option) : (SafeFileHandle * FileMetadata) option =
        if not (OperatingSystem.IsLinux()) then raise (PlatformNotSupportedException("The Users helper requires Linux."))
        let components = splitLogicalPath logicalPath
        let mutable current = openRootDirectory environment
        let rootMetadata = inspectDescriptor (current.DangerousGetHandle().ToInt32())
        validateDirectoryMetadata environment false rootMetadata
        let mutable lastMetadata = rootMetadata
        let mutable failed = false
        let mutable index = 0
        while index < components.Length && not failed do
            let directoryEntry = components[index]
            let mutable createdDirectory = false
            let fd = nativeOpenAt(current.DangerousGetHandle().ToInt32(), directoryEntry, openDirectoryFlags, 0)
            let opened =
                if fd >= 0 then fd
                else
                    let errorCode = Marshal.GetLastPInvokeError()
                    if errorCode = 2 && createDirectories then
                        if nativeMkdirAt(current.DangerousGetHandle().ToInt32(), directoryEntry, finalMode) = 0 then
                            createdDirectory <- true
                        else
                            let mkdirError = Marshal.GetLastPInvokeError()
                            if mkdirError <> 17 then fail "cannot create a required host directory"
                        let createdFd = nativeOpenAt(current.DangerousGetHandle().ToInt32(), directoryEntry, openDirectoryFlags, 0)
                        if createdFd < 0 then fail "cannot safely open a created host directory"
                        if createdDirectory && nativeFchmod(createdFd, finalMode) <> 0 then
                            nativeClose createdFd |> ignore
                            fail "cannot set safe permissions on a created host directory"
                        createdFd
                    elif errorCode = 2 then
                        failed <- true
                        -1
                    else fail "cannot safely open a host directory"
            if opened >= 0 then
                let next = new SafeFileHandle(nativeint opened, true)
                let metadata = inspectDescriptor opened
                if index = components.Length - 1 then
                    match finalOwner with
                    | Some owner when metadata.UserId <> owner -> fail "a host directory has an unexpected owner"
                    | _ -> ()
                    if metadata.FileType <> directoryType then fail "a required host path is not a real directory"
                    if (metadata.Mode &&& 0o022) <> 0 then fail "a host directory is group- or world-writable"
                else
                    validateDirectoryMetadata environment false metadata
                if createDirectories && (nativeFsync opened <> 0 || nativeFsync(current.DangerousGetHandle().ToInt32()) <> 0) then
                    next.Dispose()
                    fail "cannot synchronize the Users ownership directory chain"
                current.Dispose()
                current <- next
                lastMetadata <- metadata
            index <- index + 1
        if failed then
            current.Dispose()
            None
        else Some(current, lastMetadata)

    let private requireRootIfProduction (environment: HostEnvironment) : unit =
        if isProductionRoot environment && nativeGetEffectiveUserId() <> 0u then fail "the Users helper requires root privileges"

    let private validateSecureOwner (environment: HostEnvironment) (metadata: FileMetadata) (description: string) : unit =
        let expected = effectiveOwner environment
        if metadata.UserId <> expected then fail (description + " is not owned by the host administrator")
        if (metadata.Mode &&& 0o077) <> 0 then fail (description + " permissions are not private")
    let private validateSecureRegularFile (environment: HostEnvironment) (metadata: FileMetadata) (description: string) : unit =
        if metadata.FileType <> regularType then fail (description + " is not a regular file")
        validateSecureOwner environment metadata description
        if metadata.LinkCount <> 1u then fail (description + " has an unexpected hard-link count")

    let private ensureStateDirectory (environment: HostEnvironment) (create: bool) : string option =
        match openDirectoryChain environment ownerDirectory create 0o700 None with
        | None -> None
        | Some(handle, metadata) ->
            use handle = handle
            validateSecureOwner environment metadata "Users ownership directory"
            Some(actualPath environment ownerDirectory)

    let private readBoundedText (reader: StreamReader) (maximumCharacters: int) (description: string) : string =
        let builder = StringBuilder(min maximumCharacters 4096)
        let buffer = Array.zeroCreate<char> 4096
        let mutable finished = false
        while not finished do
            let count = reader.Read(buffer, 0, buffer.Length)
            if count = 0 then
                finished <- true
            elif builder.Length > maximumCharacters - count then
                fail (description + " exceeds its size limit")
            else
                builder.Append(buffer, 0, count) |> ignore
        builder.ToString()
    let private readHostFile (environment: HostEnvironment) (logicalPath: string) (optional: bool) : string option =
        let components = splitLogicalPath logicalPath
        if components.Length = 0 then fail "host file path must name a regular file"
        let directory = Path.GetDirectoryName logicalPath
        let name = Path.GetFileName logicalPath
        match openDirectoryChain environment directory false 0o700 None with
        | None when optional -> None
        | None -> fail ("required host file " + logicalPath + " is missing")
        | Some(directoryHandle, _) ->
            use directoryHandle = directoryHandle
            let descriptor = nativeOpenAt(directoryHandle.DangerousGetHandle().ToInt32(), name, openReadOnlyFlags, 0)
            if descriptor < 0 then
                let errorCode = Marshal.GetLastPInvokeError()
                if errorCode = 2 && optional then None
                elif errorCode = 2 then fail ("required host file " + logicalPath + " is missing")
                else fail ("cannot safely read host file " + logicalPath)
            else
                let handle = new SafeFileHandle(nativeint descriptor, true)
                try
                    let metadata = inspectDescriptor descriptor
                    if metadata.FileType <> regularType then fail ("host file " + logicalPath + " is not a regular file")
                    if metadata.Size > 16UL * 1024UL * 1024UL then fail ("host file " + logicalPath + " exceeds its size limit")
                    use stream = new FileStream(handle, FileAccess.Read)
                    use reader = new StreamReader(stream, strictUtf8, false)
                    let text = readBoundedText reader (16 * 1024 * 1024) ("host file " + logicalPath)
                    Some text
                with _ ->
                    if not handle.IsClosed then handle.Dispose()
                    reraise ()

    let private readTextFile (environment: HostEnvironment) (logicalPath: string) : string =
        readHostFile environment logicalPath false |> Option.get

    let private readOptionalTextFile (environment: HostEnvironment) (logicalPath: string) : string option =
        readHostFile environment logicalPath true

    let private safeFileContentsAt (directoryFileDescriptor: int) (fileName: string) (expectedUid: uint32) : string option =
        let descriptor = nativeOpenAt(directoryFileDescriptor, fileName, openReadOnlyFlags, 0)
        if descriptor < 0 then
            let errorCode = Marshal.GetLastPInvokeError()
            if errorCode = 2 then None
            else fail "cannot safely open an account authorization file"
        else
            let handle = new SafeFileHandle(nativeint descriptor, true)
            try
                let metadata = inspectDescriptor descriptor
                if metadata.FileType <> regularType || metadata.UserId <> expectedUid || (metadata.Mode &&& 0o022) <> 0 || metadata.LinkCount <> 1u then
                    fail "an account authorization file has unsafe ownership or permissions"
                if metadata.Size > uint64 maximumAuthorizedKeysBytes then fail "an account authorization file exceeds the size limit"
                use stream = new FileStream(handle, FileAccess.Read)
                use reader = new StreamReader(stream, strictUtf8, false)
                let text = readBoundedText reader maximumAuthorizedKeysBytes "an account authorization file"
                Some text
            with _ ->
                if not handle.IsClosed then handle.Dispose()
                reraise ()

    let private writeAll (descriptor: int) (contents: byte array) : unit =
        let mutable offset = 0
        while offset < contents.Length do
            let remaining = contents.Length - offset
            let mutable written = nativeWrite(descriptor, contents[offset..], unativeint remaining).ToInt32()
            if written < 0 then
                let errorCode = Marshal.GetLastPInvokeError()
                if errorCode <> 4 then fail "cannot write an account authorization file"
            elif written = 0 then fail "cannot complete an account authorization file write"
            else offset <- offset + written

    let private atomicWriteAt (directoryFileDescriptor: int) (fileName: string) (owner: uint32) (group: uint32) (contents: string) : unit =
        if strictUtf8.GetByteCount contents > maximumAuthorizedKeysBytes then fail "an account authorization file exceeds the size limit"
        let temporaryName = ".keroosha-users-" + Guid.NewGuid().ToString("N")
        let descriptor = nativeOpenAt(directoryFileDescriptor, temporaryName, openWriteFlags, 0o600)
        if descriptor < 0 then fail "cannot safely create an account authorization file"
        let handle = new SafeFileHandle(nativeint descriptor, true)
        let mutable temporaryExists = true
        try
            if nativeFchown(descriptor, owner, group) <> 0 then fail "cannot set account authorization file ownership"
            if nativeFchmod(descriptor, 0o600) <> 0 then fail "cannot set account authorization file permissions"
            let bytes = strictUtf8.GetBytes contents
            writeAll descriptor bytes
            if nativeFsync descriptor <> 0 then fail "cannot synchronize an account authorization file"
            let intended = inspectDescriptor descriptor
            match inspectAt directoryFileDescriptor fileName with
            | Some metadata when metadata.FileType <> regularType -> fail "refusing to replace a non-regular account authorization file"
            | Some metadata when metadata.UserId <> owner || metadata.LinkCount <> 1u || (metadata.Mode &&& 0o022) <> 0 -> fail "refusing to replace an unsafe account authorization file"
            | _ -> ()
            if nativeRenameAt(directoryFileDescriptor, temporaryName, directoryFileDescriptor, fileName) <> 0 then fail "cannot atomically install an account authorization file"
            temporaryExists <- false
            match inspectAt directoryFileDescriptor fileName with
            | Some installed
                when installed.FileType = regularType
                     && installed.UserId = owner
                     && installed.GroupId = group
                     && installed.LinkCount = 1u
                     && installed.Inode = intended.Inode
                     && installed.DeviceMajor = intended.DeviceMajor
                     && installed.DeviceMinor = intended.DeviceMinor -> ()
            | _ -> fail "installed authorized_keys entry is not the intended file"
            if nativeFsync directoryFileDescriptor <> 0 then fail "cannot synchronize an account authorization directory"
        finally
            if not handle.IsClosed then handle.Dispose()
            if temporaryExists then nativeUnlinkAt(directoryFileDescriptor, temporaryName, 0) |> ignore
    let private createOrOpenSshDirectory (environment: HostEnvironment) (userName: string) (home: string) (uid: uint32) (create: bool) : (SafeFileHandle * FileMetadata) option =
        let parent = Path.GetDirectoryName home
        let name = Path.GetFileName home
        if String.IsNullOrEmpty parent || String.IsNullOrEmpty name then fail "account home path is invalid"
        match openDirectoryChain environment parent false 0o700 None with
        | None -> None
        | Some(parentHandle, parentMetadata) ->
            use parentHandle = parentHandle
            validateDirectoryMetadata environment false parentMetadata
            let homeFd = nativeOpenAt(parentHandle.DangerousGetHandle().ToInt32(), name, openDirectoryFlags, 0)
            let openedHome =
                if homeFd >= 0 then homeFd
                else
                    let errorCode = Marshal.GetLastPInvokeError()
                    if errorCode = 2 then -1 else fail "cannot safely open an account home directory"
            if openedHome < 0 then None
            else
                let homeHandle = new SafeFileHandle(nativeint openedHome, true)
                try
                    let homeMetadata = inspectDescriptor openedHome
                    if homeMetadata.FileType <> directoryType || homeMetadata.UserId <> uid || (homeMetadata.Mode &&& 0o022) <> 0 then
                        fail "account home directory ownership or permissions are unsafe"
                    let sshFd = nativeOpenAt(openedHome, ".ssh", openDirectoryFlags, 0)
                    let openedSsh =
                        if sshFd >= 0 then sshFd
                        else
                            let errorCode = Marshal.GetLastPInvokeError()
                            if errorCode = 2 && create then
                                let sshPath = Path.Combine(actualPath environment home, ".ssh")
                                try
                                    let result =
                                        environment.Run
                                            "runuser"
                                            [ "--user"; userName; "--"; "/usr/bin/mkdir"; "--mode=0700"; "--"; sshPath ]
                                            None
                                    if result.ExitCode <> 0 then fail "cannot create account .ssh directory"
                                with
                                | :? BackendError -> reraise ()
                                | _ -> fail "cannot run host command runuser"
                                let created = nativeOpenAt(openedHome, ".ssh", openDirectoryFlags, 0)
                                if created < 0 then fail "cannot safely open a created account .ssh directory"
                                if nativeFsync created <> 0 || nativeFsync openedHome <> 0 then
                                    nativeClose created |> ignore
                                    fail "cannot synchronize a created account .ssh directory"
                                created
                            elif errorCode = 2 then -1
                            else fail "cannot safely open an account .ssh directory"
                    if openedSsh < 0 then
                        homeHandle.Dispose()
                        None
                    else
                        let sshHandle = new SafeFileHandle(nativeint openedSsh, true)
                        let sshMetadata = inspectDescriptor openedSsh
                        if sshMetadata.FileType <> directoryType || sshMetadata.UserId <> uid || (sshMetadata.Mode &&& 0o022) <> 0 then
                            sshHandle.Dispose()
                            fail "account .ssh directory ownership or permissions are unsafe"
                        homeHandle.Dispose()
                        Some(sshHandle, sshMetadata)
                with _ ->
                    if not homeHandle.IsClosed then homeHandle.Dispose()
                    reraise ()

    let private parseInteger (value: string) : int option =
        let mutable parsed = 0
        if Int32.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, &parsed) then Some parsed else None

    let private parseOptionalInteger (value: string) : int option =
        if String.IsNullOrEmpty value || value = "-1" then None
        else parseInteger value

    let private parseLocalState (environment: HostEnvironment) : LocalState =
        let parseFields (path: string) (fieldCount: int) =
            readTextFile environment path
            |> fun text -> text.Split([| '\n' |], StringSplitOptions.RemoveEmptyEntries)
            |> Array.map (fun line ->
                let fields = line.TrimEnd('\r').Split(':')
                if fields.Length <> fieldCount then fail ("host file " + path + " contains a malformed record")
                fields)
        let users: Map<string, UserAccount> =
            parseFields "/etc/passwd" 7
            |> Array.map (fun fields ->
                let uid = parseInteger fields[2] |> Option.defaultWith (fun () -> fail "host passwd contains an invalid UID")
                let gid = parseInteger fields[3] |> Option.defaultWith (fun () -> fail "host passwd contains an invalid GID")
                if uid < 0 || gid < 0 || String.IsNullOrEmpty fields[0] then fail "host passwd contains an invalid identity"
                fields[0], { Name = fields[0]; Uid = uid; Gid = gid; Description = fields[4]; Home = fields[5]; Shell = fields[6] })
            |> Map.ofArray
        let groups: Map<string, GroupAccount> =
            parseFields "/etc/group" 4
            |> Array.map (fun fields ->
                let gid = parseInteger fields[2] |> Option.defaultWith (fun () -> fail "host group contains an invalid GID")
                if gid < 0 || String.IsNullOrEmpty fields[0] then fail "host group contains an invalid identity"
                let members =
                    if String.IsNullOrEmpty fields[3] then Set.empty
                    else fields[3].Split(',', StringSplitOptions.RemoveEmptyEntries) |> Set.ofArray
                fields[0], { Name = fields[0]; Gid = gid; Members = members })
            |> Map.ofArray
        let shadows: Map<string, ShadowAccount> =
            let shadowLines =
                match readOptionalTextFile environment "/etc/shadow" with
                | Some text -> text.Split([| '\n' |], StringSplitOptions.RemoveEmptyEntries)
                | None -> fail "required host file /etc/shadow is missing"
            shadowLines
            |> Array.map (fun line ->
                let fields = line.TrimEnd('\r').Split(':')
                if fields.Length <> 9 || String.IsNullOrEmpty fields[0] then fail "host shadow contains a malformed record"
                let optional index =
                    match parseOptionalInteger fields[index] with
                    | Some value when value >= 0 -> Some value
                    | Some _ -> fail "host shadow contains an invalid password policy value"
                    | None -> None
                let expiry =
                    if String.IsNullOrEmpty fields[7] || fields[7] = "-1" then None
                    else
                        let mutable value = 0L
                        if Int64.TryParse(fields[7], NumberStyles.None, CultureInfo.InvariantCulture, &value) && value >= 0L then Some value
                        else fail "host shadow contains an invalid account expiry"
                fields[0],
                { Name = fields[0]
                  PasswordHash = fields[1]
                  MinimumDays = optional 3
                  MaximumDays = optional 4
                  WarningDays = optional 5
                  InactiveDays = optional 6
                  ExpiryDay = expiry })
            |> Map.ofArray
        if users.Count <> (parseFields "/etc/passwd" 7 |> Array.length) then fail "host passwd contains duplicate names"
        if groups.Count <> (parseFields "/etc/group" 4 |> Array.length) then fail "host group contains duplicate names"
        let shadowCount =
            readTextFile environment "/etc/shadow"
            |> fun text -> text.Split([| '\n' |], StringSplitOptions.RemoveEmptyEntries).Length
        if shadows.Count <> shadowCount then fail "host shadow contains duplicate names"
        if (users |> Map.toSeq |> Seq.map (snd >> fun user -> user.Uid) |> Set.ofSeq |> Set.count) <> users.Count then fail "host passwd contains duplicate UIDs"
        if (groups |> Map.toSeq |> Seq.map (snd >> fun group -> group.Gid) |> Set.ofSeq |> Set.count) <> groups.Count then fail "host group contains duplicate GIDs"
        if users |> Map.toSeq |> Seq.exists (fun (name, _) -> not (Map.containsKey name shadows)) then fail "host shadow is missing a local account"
        { Users = users; Groups = groups; Shadows = shadows }

    let private readBounds (environment: HostEnvironment) : IdBounds =
        let defaults =
            { UserMinimum = 1000
              UserMaximum = 60000
              SystemUserMinimum = 100
              SystemUserMaximum = 999
              GroupMinimum = 1000
              GroupMaximum = 60000
              SystemGroupMinimum = 100
              SystemGroupMaximum = 999
              UserGroupsEnabled = false
              ReservedUserIds = Set.empty
              ReservedGroupIds = Set.empty }
        let mutable bounds = defaults
        match readOptionalTextFile environment "/etc/login.defs" with
        | None -> ()
        | Some text ->
            for line in text.Split([| '\n' |], StringSplitOptions.RemoveEmptyEntries) do
                let content = (line.Split('#')[0]).Trim()
                if not (String.IsNullOrEmpty content) then
                    let fields = content.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
                    if fields.Length >= 2 then
                        let value = parseInteger fields[1]
                        match fields[0], value with
                        | "UID_MIN", Some number -> bounds <- { bounds with UserMinimum = number }
                        | "UID_MAX", Some number -> bounds <- { bounds with UserMaximum = number }
                        | "SYS_UID_MIN", Some number -> bounds <- { bounds with SystemUserMinimum = number }
                        | "SYS_UID_MAX", Some number -> bounds <- { bounds with SystemUserMaximum = number }
                        | "GID_MIN", Some number -> bounds <- { bounds with GroupMinimum = number }
                        | "GID_MAX", Some number -> bounds <- { bounds with GroupMaximum = number }
                        | "SYS_GID_MIN", Some number -> bounds <- { bounds with SystemGroupMinimum = number }
                        | "SYS_GID_MAX", Some number -> bounds <- { bounds with SystemGroupMaximum = number }
                        | "USERGROUPS_ENAB", _ -> bounds <- { bounds with UserGroupsEnabled = fields[1].Equals("yes", StringComparison.OrdinalIgnoreCase) }
                        | _ -> ()
        if bounds.UserMinimum < 1 || bounds.UserMaximum < bounds.UserMinimum || bounds.SystemUserMinimum < 1 || bounds.SystemUserMaximum < bounds.SystemUserMinimum || bounds.GroupMinimum < 1 || bounds.GroupMaximum < bounds.GroupMinimum || bounds.SystemGroupMinimum < 1 || bounds.SystemGroupMaximum < bounds.SystemGroupMinimum then
            fail "host login.defs contains invalid account ID ranges"
        bounds

    let private validateName (field: string) (name: string) : string =
        if isNull name || not (validName.IsMatch name) then fail (field + " must be a conservative local account name")
        name

    let private ensureObject (allowed: Set<string>) (element: JsonElement) (description: string) : unit =
        if element.ValueKind <> JsonValueKind.Object then fail (description + " must be an object")
        let names = HashSet<string>(StringComparer.Ordinal)
        for property in element.EnumerateObject() do
            if not (names.Add property.Name) then fail (description + " contains a duplicate property")
            if not (Set.contains property.Name allowed) then fail (description + " contains an unsupported property")
    let private tryProperty (element: JsonElement) (name: string) : JsonElement option =
        let mutable value = Unchecked.defaultof<JsonElement>
        if element.TryGetProperty(name, &value) then Some value else None

    let private requiredString (element: JsonElement) (name: string) : string =
        match tryProperty element name with
        | Some value when value.ValueKind = JsonValueKind.String ->
            match value.GetString() with
            | null -> fail (name + " must not be null")
            | text -> text
        | _ -> fail (name + " must be a string")

    let private optionalString (element: JsonElement) (name: string) : string option =
        match tryProperty element name with
        | None -> None
        | Some value when value.ValueKind = JsonValueKind.String ->
            match value.GetString() with
            | null -> fail (name + " must not be null")
            | text -> Some text
        | Some _ -> fail (name + " must be a string")

    let private requiredBool (element: JsonElement) (name: string) : bool =
        match tryProperty element name with
        | Some value when value.ValueKind = JsonValueKind.True -> true
        | Some value when value.ValueKind = JsonValueKind.False -> false
        | _ -> fail (name + " must be a boolean")

    let private optionalBool (element: JsonElement) (name: string) : bool option =
        match tryProperty element name with
        | None -> None
        | Some value when value.ValueKind = JsonValueKind.True -> Some true
        | Some value when value.ValueKind = JsonValueKind.False -> Some false
        | Some _ -> fail (name + " must be a boolean")

    let private optionalInt (element: JsonElement) (name: string) : int option =
        match tryProperty element name with
        | None -> None
        | Some value when value.ValueKind = JsonValueKind.Number ->
            let mutable parsed = 0
            if value.TryGetInt32(&parsed) then Some parsed else fail (name + " must be a signed 32-bit integer")
        | Some _ -> fail (name + " must be a signed 32-bit integer")

    let private stringArray (element: JsonElement) (name: string) : string list =
        match tryProperty element name with
        | None -> []
        | Some value when value.ValueKind = JsonValueKind.Array ->
            value.EnumerateArray()
            |> Seq.map (fun item ->
                if item.ValueKind <> JsonValueKind.String then fail (name + " items must be strings")
                match item.GetString() with null -> fail (name + " items must not be null") | text -> text)
            |> Seq.toList
        | Some _ -> fail (name + " must be an array")

    let private optionalStringArray (element: JsonElement) (name: string) : string list option =
        match tryProperty element name with
        | None -> None
        | Some _ -> Some(stringArray element name)

    let private parseRange (element: JsonElement) (description: string) : IdRange =
        ensureObject (Set.ofList [ "start"; "count" ]) element description
        let startValue = optionalInt element "start" |> Option.defaultWith (fun () -> fail (description + ".start is required"))
        let countValue = optionalInt element "count" |> Option.defaultWith (fun () -> fail (description + ".count is required"))
        if startValue <= 0 || countValue <= 0 then fail (description + " start and count must be positive")
        let finish = uint64 startValue + uint64 countValue - 1UL
        if finish > uint64 UInt32.MaxValue then fail (description + " exceeds the subordinate ID range")
        { Start = uint32 startValue; Count = uint32 countValue }

    let private rangesOverlap (left: IdRange) (right: IdRange) : bool =
        let leftEnd = uint64 left.Start + uint64 left.Count - 1UL
        let rightEnd = uint64 right.Start + uint64 right.Count - 1UL
        uint64 left.Start <= rightEnd && uint64 right.Start <= leftEnd

    let private validateRanges (description: string) (ranges: IdRange list) : unit =
        for i in 0 .. ranges.Length - 1 do
            for j in i + 1 .. ranges.Length - 1 do
                if rangesOverlap ranges[i] ranges[j] then fail (description + " ranges overlap")

    let private parseRanges (element: JsonElement) (name: string) : IdRange list option =
        match tryProperty element name with
        | None -> None
        | Some values when values.ValueKind = JsonValueKind.Array ->
            let ranges = values.EnumerateArray() |> Seq.map (fun item -> parseRange item (name + " item")) |> Seq.toList
            validateRanges name ranges
            Some ranges
        | Some _ -> fail (name + " must be an array")

    let private parseKey (element: JsonElement) : KeySpec =
        ensureObject
            (Set.ofList [ "id"; "publicKey"; "comment"; "restrict"; "allowPty"; "allowAgentForwarding"; "allowPortForwarding"; "allowX11Forwarding"; "allowUserRc"; "allowFrom"; "command"; "expires"; "permitOpen"; "permitListen"; "verifyRequired" ])
            element
            "authorized key"
        let id = requiredString element "id"
        if not (validKeyId.IsMatch id) then fail "authorized key id has an unsafe format"
        let publicKey = requiredString element "publicKey"
        if hasControl publicKey || publicKey.Length > 16384 then fail "authorized public key is malformed"
        let keyFields = publicKey.Split([| ' '; '\t' |], StringSplitOptions.RemoveEmptyEntries)
        if keyFields.Length < 2 then fail "authorized public key must contain an algorithm and key material"
        let keyType, keyData = keyFields[0], keyFields[1]
        let comment =
            match optionalString element "comment" with
            | Some value when hasControl value || value.Length > 1024 -> fail "authorized key comment is unsafe"
            | Some value -> Some value
            | None when keyFields.Length > 2 -> Some(String.Join(" ", keyFields[2..]))
            | None -> None
        let bytes =
            try Convert.FromBase64String keyData
            with _ -> fail "authorized public key material is not valid base64"
        if bytes.Length < 16 || bytes.Length > 8192 then fail "authorized public key material has an invalid size"
        let mutable offset = 0
        let readUInt32 () =
            if offset + 4 > bytes.Length then fail "authorized public key material is truncated"
            let value =
                (uint32 bytes[offset] <<< 24)
                ||| (uint32 bytes[offset + 1] <<< 16)
                ||| (uint32 bytes[offset + 2] <<< 8)
                ||| uint32 bytes[offset + 3]
            offset <- offset + 4
            value
        let readField () =
            let length = readUInt32 ()
            if length > uint32 (bytes.Length - offset) then fail "authorized public key material is malformed"
            if length = 0u then Array.empty
            else
                let result = bytes[offset .. offset + int length - 1]
                offset <- offset + int length
                result
        let readString () =
            let value = readField ()
            strictUtf8.GetString value
        let algorithm = readString ()
        if not (String.Equals(algorithm, keyType, StringComparison.Ordinal)) then fail "authorized public key algorithm does not match its encoded material"
        let readPositiveInteger () =
            let value = readField ()
            if value.Length = 0 || (value.Length = 1 && value[0] = 0uy) || (value[0] &&& 0x80uy) <> 0uy then fail "authorized public key contains an invalid integer"
            value
        match keyType with
        | "ssh-ed25519" ->
            let publicValue = readField ()
            if publicValue.Length <> 32 then fail "authorized Ed25519 key has an invalid length"
        | "ssh-rsa" ->
            let exponent = readPositiveInteger ()
            let modulus = readPositiveInteger ()
            let exponentValue = exponent |> Array.fold (fun number byte -> (number <<< 8) + bigint byte) BigInteger.Zero
            let modulusBits =
                let leadingBits = 32 - System.Numerics.BitOperations.LeadingZeroCount(uint32 modulus[0])
                (modulus.Length - 1) * 8 + leadingBits
            if exponentValue < 3I || exponentValue.IsEven || modulusBits < 2048 then fail "authorized RSA key is too small or invalid"
        | ("ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521") as algorithmName ->
            let curve = readString ()
            let expectedCurve = algorithmName.Substring("ecdsa-sha2-".Length)
            let point = readField ()
            let expectedLength = if expectedCurve = "nistp256" then 65 else if expectedCurve = "nistp384" then 97 else 133
            if curve <> expectedCurve || point.Length <> expectedLength || point[0] <> 4uy then fail "authorized ECDSA key has invalid curve material"
        | "sk-ssh-ed25519@openssh.com" ->
            let publicValue = readField ()
            let application = readString ()
            if publicValue.Length <> 32 || String.IsNullOrWhiteSpace application then fail "authorized security key material is invalid"
        | "sk-ecdsa-sha2-nistp256@openssh.com" ->
            let curve = readString ()
            let point = readField ()
            let application = readString ()
            if curve <> "nistp256" || point.Length <> 65 || point[0] <> 4uy || String.IsNullOrWhiteSpace application then fail "authorized security key material is invalid"
        | "ssh-dss" ->
            for _ in 1 .. 4 do readPositiveInteger () |> ignore
        | _ -> fail "authorized key algorithm is unsupported"
        if offset <> bytes.Length then fail "authorized public key material contains trailing data"
        let fromValues = stringArray element "allowFrom"
        let command = optionalString element "command"
        let permitOpen = stringArray element "permitOpen"
        let permitListen = stringArray element "permitListen"
        let expires =
            match optionalString element "expires" with
            | None -> None
            | Some value ->
                let mutable timestamp = DateTimeOffset.MinValue
                if not (value.EndsWith("Z", StringComparison.Ordinal)) || not (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal ||| DateTimeStyles.AdjustToUniversal, &timestamp)) || timestamp.Offset <> TimeSpan.Zero then
                    fail "authorized key expiry must be a UTC timestamp"
                Some timestamp
        for value in permitOpen @ permitListen do
            if value.Length > 1024 || not (forwardEndpointPattern.IsMatch value) then fail "authorized key forwarding endpoint is malformed"
            let port = value.Substring(value.LastIndexOf(':') + 1)
            if port <> "*" then
                let mutable parsedPort = 0
                if not (Int32.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, &parsedPort)) || parsedPort < 1 || parsedPort > 65535 then
                    fail "authorized key forwarding port is out of range"
        for value in fromValues do
            if String.IsNullOrEmpty value || hasControl value || value.Length > 1024 || value.Contains(',') then
                fail "authorized key source pattern is unsafe"
        match command with
        | Some value when String.IsNullOrEmpty value || hasControl value || value.Length > 4096 -> fail "authorized key command is unsafe"
        | _ -> ()
        let verifyRequired = optionalBool element "verifyRequired" |> Option.defaultValue false
        if verifyRequired && not (keyType.StartsWith("sk-", StringComparison.Ordinal)) then fail "verifyRequired applies only to security keys"
        { Id = id
          KeyType = keyType
          KeyData = keyData
          Comment = comment
          Restrict = optionalBool element "restrict" |> Option.defaultValue false
          AllowPty = optionalBool element "allowPty"
          AllowAgentForwarding = optionalBool element "allowAgentForwarding"
          AllowPortForwarding = optionalBool element "allowPortForwarding"
          AllowX11Forwarding = optionalBool element "allowX11Forwarding"
          AllowUserRc = optionalBool element "allowUserRc"
          AllowFrom = fromValues
          Command = command
          Expires = expires
          PermitOpen = permitOpen
          PermitListen = permitListen
          VerifyRequired = verifyRequired }

    let private parseGroup (element: JsonElement) : GroupSpec =
        ensureObject (Set.ofList [ "name"; "gid"; "kind"; "existing"; "state" ]) element "group"
        let name = requiredString element "name" |> validateName "group name"
        let gid = optionalInt element "gid"
        match gid with Some value when value < 0 -> fail "group gid must be non-negative" | _ -> ()
        let kind = optionalString element "kind"
        match kind with Some value when value <> "human" && value <> "system" -> fail "group kind must be human or system" | _ -> ()
        let existing = optionalString element "existing" |> Option.defaultValue "reject"
        if existing <> "reject" && existing <> "adopt" then fail "group existing must be reject or adopt"
        let state = optionalString element "state" |> Option.defaultValue "present"
        if state <> "present" && state <> "absent" then fail "group state must be present or absent"
        if state = "absent" && (gid.IsSome || kind.IsSome) then fail "absent groups may only specify name, existing, and state"
        { Name = name; Gid = gid; Kind = kind; Existing = existing; State = state }

    let private parseHome (element: JsonElement) : HomeSpec =
        ensureObject (Set.ofList [ "kind"; "path"; "mode"; "skeleton" ]) element "home"
        let kind = requiredString element "kind"
        if kind <> "create" && kind <> "existing" && kind <> "none" then fail "home kind must be create, existing, or none"
        let path = optionalString element "path"
        let mode = optionalInt element "mode"
        match mode with Some value when value < 0 || value > 0o777 -> fail "home mode must be between 0000 and 0777" | _ -> ()
        let skeleton = optionalString element "skeleton"
        let validateHomePath field value =
            if String.IsNullOrWhiteSpace value || not (Path.IsPathRooted value) || hasControl value then fail (field + " must be an absolute safe path")
            let normalized = try Path.GetFullPath value with _ -> fail (field + " is invalid")
            if normalized <> value || normalized = Path.GetPathRoot normalized then fail (field + " must be a canonical non-root path")
            for segment in value.TrimStart('/').Split('/') do
                if String.IsNullOrEmpty segment || segment = "." || segment = ".." then fail (field + " contains an unsafe path component")
            value
        let path = path |> Option.map (validateHomePath "home path")
        let skeleton = skeleton |> Option.map (validateHomePath "home skeleton")
        match kind, path with
        | "create", None | "existing", None -> fail "create and existing homes require a path"
        | "none", Some _ -> fail "home none cannot specify a path"
        | "none", None when mode.IsSome || skeleton.IsSome -> fail "home none cannot specify mode or skeleton"
        | _ -> ()
        if kind <> "create" && skeleton.IsSome then fail "home skeleton is supported only when creating a home"
        { Kind = kind; Path = path; Mode = mode; Skeleton = skeleton }

    let private parsePassword (element: JsonElement) : PasswordSpec =
        ensureObject (Set.ofList [ "kind"; "hash"; "update" ]) element "password"
        let kind = requiredString element "kind"
        let update = optionalString element "update" |> Option.defaultValue "onCreate"
        if update <> "always" && update <> "onCreate" then fail "password update must be always or onCreate"
        match kind with
        | "locked" ->
            if (optionalString element "hash").IsSome || (tryProperty element "update").IsSome then fail "locked password cannot include hash or update"
            { Kind = kind; Hash = None; Update = "always" }
        | "hash" ->
            let hash = requiredString element "hash"
            if hash.Length > 4096 || hash.Length = 0 || hasControl hash || hash.Contains(':') || (hash |> Seq.exists Char.IsWhiteSpace) || not (hash.StartsWith("$", StringComparison.Ordinal)) then
                fail "password hash is malformed"
            { Kind = kind; Hash = Some hash; Update = update }
        | _ -> fail "password kind must be locked or hash"

    let private parseUser (element: JsonElement) : UserSpec =
        ensureObject (Set.ofList [ "name"; "state"; "kind"; "existing"; "uid"; "description"; "primaryGroup"; "supplementaryGroups"; "home"; "shell"; "password"; "accountExpiry"; "passwordPolicy"; "subordinateUids"; "subordinateGids"; "onDelete"; "authorizedKeys" ]) element "user"
        let name = requiredString element "name" |> validateName "user name"
        let state = optionalString element "state" |> Option.defaultValue "present"
        if state <> "present" && state <> "absent" then fail "user state must be present or absent"
        let kind = optionalString element "kind"
        match kind with Some value when value <> "human" && value <> "system" -> fail "user kind must be human or system" | _ -> ()
        let existing = optionalString element "existing" |> Option.defaultValue "reject"
        if existing <> "reject" && existing <> "adopt" then fail "user existing must be reject or adopt"
        let uid = optionalInt element "uid"
        match uid with Some value when value <= 0 -> fail "user uid must be positive; UID zero is reserved" | _ -> ()
        let description = optionalString element "description"
        match description with
        | Some value when value.Length > 256 || hasControl value || value.Contains(':') -> fail "user description is unsafe"
        | _ -> ()
        let primaryGroup =
            match tryProperty element "primaryGroup" with
            | None -> None
            | Some value ->
                ensureObject (Set.ofList [ "kind"; "name" ]) value "primaryGroup"
                let groupKind = requiredString value "kind"
                if groupKind <> "private" && groupKind <> "existing" then fail "primaryGroup kind must be private or existing"
                let groupName = optionalString value "name" |> Option.map (validateName "primary group")
                if groupKind = "existing" && groupName.IsNone then fail "existing primaryGroup requires a name"
                if groupKind = "private" && groupName.IsSome then fail "private primaryGroup cannot specify a name"
                Some(groupKind, groupName)
        let supplementary =
            match tryProperty element "supplementaryGroups" with
            | None -> None
            | Some value ->
                ensureObject (Set.ofList [ "mode"; "names" ]) value "supplementaryGroups"
                let mode = requiredString value "mode"
                if mode <> "managed" && mode <> "exclusive" then fail "supplementaryGroups mode must be managed or exclusive"
                let names = stringArray value "names" |> List.map (validateName "supplementary group")
                if names.Length <> (Set.ofList names).Count then fail "supplementaryGroups contains duplicate names"
                Some(mode, names)
        let home = tryProperty element "home" |> Option.map parseHome
        let shell = optionalString element "shell"
        match shell with
        | Some value when String.IsNullOrWhiteSpace value || not (Path.IsPathRooted value) || hasControl value || value.Contains(':') -> fail "user shell must be an absolute safe path"
        | Some value when (try Path.GetFullPath value <> value with _ -> true) -> fail "user shell must be canonical"
        | _ -> ()
        let password = tryProperty element "password" |> Option.map parsePassword
        let expiry =
            match tryProperty element "accountExpiry" with
            | None -> None
            | Some value ->
                ensureObject (Set.ofList [ "kind"; "date" ]) value "accountExpiry"
                let kind = requiredString value "kind"
                if kind = "never" then
                    if (optionalString value "date").IsSome then fail "never account expiry cannot specify date"
                    Some(kind, None)
                elif kind = "on" then
                    let date = requiredString value "date"
                    let mutable parsed = DateOnly.MinValue
                    if not (DateOnly.TryParseExact(date, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, &parsed)) then fail "account expiry date must use YYYY-MM-DD"
                    Some(kind, Some date)
                else fail "account expiry kind must be never or on"
        let passwordPolicy =
            match tryProperty element "passwordPolicy" with
            | None -> Map.empty
            | Some value ->
                ensureObject (Set.ofList [ "minDays"; "maxDays"; "warnDays"; "inactiveDays" ]) value "passwordPolicy"
                [ "minDays"; "maxDays"; "warnDays"; "inactiveDays" ]
                |> List.choose (fun field -> optionalInt value field |> Option.map (fun number -> field, number))
                |> List.fold (fun state (field, number) ->
                    if number < 0 then fail ("passwordPolicy." + field + " must be non-negative")
                    Map.add field number state) Map.empty
        match Map.tryFind "minDays" passwordPolicy, Map.tryFind "maxDays" passwordPolicy with
        | Some minimum, Some maximum when maximum > 0 && minimum > maximum -> fail "passwordPolicy maxDays must not be less than minDays"
        | _ -> ()
        let subordinateUids = parseRanges element "subordinateUids"
        let subordinateGids = parseRanges element "subordinateGids"
        let onDelete = optionalString element "onDelete"
        match onDelete with Some value when value <> "retainIdentity" -> fail "onDelete must be retainIdentity" | _ -> ()
        let authorizedKeys =
            match tryProperty element "authorizedKeys" with
            | None -> None
            | Some value ->
                ensureObject (Set.ofList [ "mode"; "keys" ]) value "authorizedKeys"
                let mode = requiredString value "mode"
                if mode <> "managed" && mode <> "exclusive" then fail "authorizedKeys mode must be managed or exclusive"
                let keysElement = tryProperty value "keys" |> Option.defaultWith (fun () -> fail "authorizedKeys.keys is required")
                if keysElement.ValueKind <> JsonValueKind.Array then fail "authorizedKeys.keys must be an array"
                let keys = keysElement.EnumerateArray() |> Seq.map parseKey |> Seq.toList
                let ids = keys |> List.map (fun key -> key.Id)
                let materials = keys |> List.map (fun key -> key.KeyType + " " + key.KeyData)
                if ids.Length <> (Set.ofList ids).Count then fail "authorizedKeys contains duplicate key identifiers"
                if materials.Length <> (Set.ofList materials).Count then fail "authorizedKeys contains duplicate key material"
                Some { Mode = mode; Keys = keys }
        if state = "absent" &&
           (kind.IsSome || uid.IsSome || description.IsSome || primaryGroup.IsSome || supplementary.IsSome || home.IsSome || shell.IsSome || password.IsSome || expiry.IsSome || not passwordPolicy.IsEmpty || subordinateUids.IsSome || subordinateGids.IsSome || authorizedKeys.IsSome || onDelete.IsSome) then
            fail "absent users may only specify name, state, and existing"
        { Name = name
          State = state
          Kind = kind
          Existing = existing
          Uid = uid
          Description = description
          PrimaryGroup = primaryGroup
          SupplementaryGroups = supplementary
          Home = home
          Shell = shell
          Password = password
          Expiry = expiry
          PasswordPolicy = passwordPolicy
          SubordinateUids = subordinateUids
          SubordinateGids = subordinateGids
          OnDelete = onDelete
          AuthorizedKeys = authorizedKeys }

    let private parseRequest (request: JsonElement) : Request =
        ensureObject (Set.ofList [ "operation"; "resourceId"; "connectionUser"; "groups"; "users" ]) request "Users request"
        let operation = requiredString request "operation"
        if operation <> "read" && operation <> "apply" && operation <> "delete" then fail "Users operation must be read, apply, or delete"
        let resourceId = requiredString request "resourceId"
        if String.IsNullOrWhiteSpace resourceId || resourceId.Length > 4096 || hasControl resourceId then fail "resourceId must be non-empty and contain no control characters"
        let connectionUser = requiredString request "connectionUser" |> validateName "connectionUser"
        let parseItems (name: string) (parser: JsonElement -> 'T) : 'T list =
            match tryProperty request name with
            | Some value when value.ValueKind = JsonValueKind.Array -> value.EnumerateArray() |> Seq.map parser |> Seq.toList
            | Some _ -> fail (name + " must be an array")
            | None -> fail (name + " is required")
        let groups = parseItems "groups" parseGroup
        let users = parseItems "users" parseUser
        let groupNames = groups |> List.map (fun group -> group.Name)
        let userNames = users |> List.map (fun user -> user.Name)
        if groupNames.Length <> (Set.ofList groupNames).Count then fail "groups contains duplicate names"
        if userNames.Length <> (Set.ofList userNames).Count then fail "users contains duplicate names"
        let absentGroupNames = groups |> List.filter (fun group -> group.State = "absent") |> List.map (fun group -> group.Name) |> Set.ofList
        for user in users do
            if user.State = "present" then
                let primaryName =
                    match user.PrimaryGroup with
                    | Some("private", _) -> Some user.Name
                    | Some("existing", Some name) -> Some name
                    | None when user.Existing = "reject" -> Some user.Name
                    | _ -> None
                if primaryName |> Option.exists (fun name -> Set.contains name absentGroupNames) then
                    fail "a present user cannot use a group explicitly declared absent"
                match user.SupplementaryGroups with
                | Some(_, names) when names |> List.exists (fun name -> Set.contains name absentGroupNames) ->
                    fail "a present user cannot use a group explicitly declared absent"
                | _ -> ()
        { Operation = operation; ResourceId = resourceId; ConnectionUser = connectionUser; Groups = groups; Users = users }

    let private ownerDigest (ownerId: string) =
        try SHA256.HashData(strictUtf8.GetBytes ownerId) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()
        with :? EncoderFallbackException -> fail "resourceId is not valid UTF-8"

    let private journalPath (ownerId: string) : string = ownerDirectory + "/" + ownerDigest ownerId + ".json"

    let private jsonString (value: string) : JsonNode = JsonValue.Create(value) :> JsonNode
    let private jsonInt (value: int) : JsonNode = JsonValue.Create(value) :> JsonNode
    let private jsonUInt (value: uint32) : JsonNode = JsonValue.Create(value) :> JsonNode
    let private jsonBool (value: bool) : JsonNode = JsonValue.Create(value) :> JsonNode

    let private nodeString (node: JsonNode) : string option =
        if isNull node then None else Some(node.GetValue<string>())

    let private nodeInt (node: JsonNode) : int option =
        if isNull node then None else Some(node.GetValue<int>())

    let private nodeBool (node: JsonNode) : bool option =
        if isNull node then None else Some(node.GetValue<bool>())

    let private nodeRanges (node: JsonNode) : Set<IdRange> =
        if isNull node then Set.empty
        else
            node.AsArray()
            |> Seq.map (fun (value: JsonNode) -> { Start = value["start"].GetValue<uint32>(); Count = value["count"].GetValue<uint32>() })
            |> Set.ofSeq

    let private rangesNode (ranges: seq<IdRange>) : JsonNode =
        let values = JsonArray()
        for range in ranges do
            let item = JsonObject()
            item["start"] <- jsonUInt range.Start
            item["count"] <- jsonUInt range.Count
            values.Add item
        values :> JsonNode

    let private stringsNode (values: seq<string>) : JsonNode =
        let result = JsonArray()
        for value in values do result.Add(jsonString value)
        result :> JsonNode

    let private parseJournal (ownerId: string) (node: JsonObject) : Journal =
        if node["version"].GetValue<int>() <> 1 || node["ownerId"].GetValue<string>() <> ownerId then fail "Users ownership journal identity is inconsistent"
        let groups: Map<string, GroupOwnership> =
            node["groups"].AsObject()
            |> Seq.map (fun pair ->
                let record: JsonObject = pair.Value.AsObject()
                pair.Key,
                { Gid = record["gid"].GetValue<int>()
                  Identity = record["identity"].GetValue<string>()
                  Kind = nodeString record["kind"] })
            |> Map.ofSeq
        let users: Map<string, UserOwnership> =
            node["users"].AsObject()
            |> Seq.map (fun pair ->
                let record: JsonObject = pair.Value.AsObject()
                let strings (name: string) = if isNull record[name] then Set.empty else record[name].AsArray() |> Seq.map (fun value -> value.GetValue<string>()) |> Set.ofSeq
                let keyLines (name: string) = if isNull record[name] then [] else record[name].AsArray() |> Seq.map (fun value -> value.GetValue<string>()) |> Seq.toList
                let optionalKeyLines (name: string) = if isNull record[name] then None else Some(keyLines name)
                pair.Key,
                { Uid = record["uid"].GetValue<int>()
                  Gid = record["gid"].GetValue<int>()
                  Identity = record["identity"].GetValue<string>()
                  CreationComplete = record["creationComplete"].GetValue<bool>()
                  CreationHomeKind = nodeString record["creationHomeKind"]
                  CreationHomePath = nodeString record["creationHomePath"]
                  CreationHomeMode = nodeInt record["creationHomeMode"]
                  CreationHomeSkeleton = nodeString record["creationHomeSkeleton"]
                  CreationShell = nodeString record["creationShell"]
                  MembershipsAdded = strings "membershipsAdded"
                  KeyMode = nodeString record["keyMode"]
                  KeyHome = nodeString record["keyHome"]
                  KeyLines = keyLines "keyLines"
                  KeyPendingBefore = optionalKeyLines "keyPendingBefore"
                  KeyPendingAfter = optionalKeyLines "keyPendingAfter"
                  KeyPendingDesired = optionalKeyLines "keyPendingDesired"
                  KeyPendingMode = nodeString record["keyPendingMode"]
                  KeyPendingHome = nodeString record["keyPendingHome"]
                  KeyPendingAdded = strings "keyPendingAdded"
                  KeysAdded = strings "keysAdded"
                  SubordinateUidsAdded = nodeRanges record["subordinateUidsAdded"]
                  SubordinateGidsAdded = nodeRanges record["subordinateGidsAdded"]
                  PasswordKind = nodeString record["passwordKind"]
                  PasswordDigest = nodeString record["passwordDigest"] })
            |> Map.ofSeq
        { OwnerId = ownerId; Groups = groups; Users = users }

    let private journalNode (journal: Journal) : JsonObject =
        let root = JsonObject()
        root["version"] <- jsonInt 1
        root["ownerId"] <- jsonString journal.OwnerId
        let groups = JsonObject()
        for KeyValue(name, record) in journal.Groups do
            let item = JsonObject()
            item["gid"] <- jsonInt record.Gid
            item["identity"] <- jsonString record.Identity
            item["kind"] <- record.Kind |> Option.map jsonString |> Option.defaultValue null
            groups[name] <- item
        root["groups"] <- groups
        let users = JsonObject()
        for KeyValue(name, record) in journal.Users do
            let item = JsonObject()
            item["uid"] <- jsonInt record.Uid
            item["gid"] <- jsonInt record.Gid
            item["identity"] <- jsonString record.Identity
            item["creationComplete"] <- jsonBool record.CreationComplete
            item["creationHomeKind"] <- record.CreationHomeKind |> Option.map jsonString |> Option.defaultValue null
            item["creationHomePath"] <- record.CreationHomePath |> Option.map jsonString |> Option.defaultValue null
            item["creationHomeMode"] <- record.CreationHomeMode |> Option.map jsonInt |> Option.defaultValue null
            item["creationHomeSkeleton"] <- record.CreationHomeSkeleton |> Option.map jsonString |> Option.defaultValue null
            item["creationShell"] <- record.CreationShell |> Option.map jsonString |> Option.defaultValue null
            item["membershipsAdded"] <- stringsNode record.MembershipsAdded
            item["keyMode"] <- record.KeyMode |> Option.map jsonString |> Option.defaultValue null
            item["keyHome"] <- record.KeyHome |> Option.map jsonString |> Option.defaultValue null
            item["keyLines"] <- stringsNode record.KeyLines
            item["keyPendingBefore"] <- record.KeyPendingBefore |> Option.map stringsNode |> Option.defaultValue null
            item["keyPendingAfter"] <- record.KeyPendingAfter |> Option.map stringsNode |> Option.defaultValue null
            item["keyPendingDesired"] <- record.KeyPendingDesired |> Option.map stringsNode |> Option.defaultValue null
            item["keyPendingMode"] <- record.KeyPendingMode |> Option.map jsonString |> Option.defaultValue null
            item["keyPendingHome"] <- record.KeyPendingHome |> Option.map jsonString |> Option.defaultValue null
            item["keyPendingAdded"] <- stringsNode record.KeyPendingAdded
            item["keysAdded"] <- stringsNode record.KeysAdded
            item["subordinateUidsAdded"] <- rangesNode record.SubordinateUidsAdded
            item["subordinateGidsAdded"] <- rangesNode record.SubordinateGidsAdded
            item["passwordKind"] <- record.PasswordKind |> Option.map jsonString |> Option.defaultValue null
            item["passwordDigest"] <- record.PasswordDigest |> Option.map jsonString |> Option.defaultValue null
            users[name] <- item
        root["users"] <- users
        root

    let private withUserUserRecord (journal: Journal) (name: string) (record: UserOwnership) : Journal =
        { journal with Users = Map.add name record journal.Users }
    let private withoutUserUserRecord (journal: Journal) (name: string) : Journal =
        { journal with Users = Map.remove name journal.Users }
    let private withGroupRecord (journal: Journal) (name: string) (record: GroupOwnership) : Journal =
        { journal with Groups = Map.add name record journal.Groups }
    let private withoutGroupRecord (journal: Journal) (name: string) : Journal =
        { journal with Groups = Map.remove name journal.Groups }

    let private readJournal (environment: HostEnvironment) (ownerId: string) : Journal option =
        match ensureStateDirectory environment false with
        | None -> None
        | Some _ ->
            match openDirectoryChain environment ownerDirectory false 0o700 None with
            | None -> None
            | Some(directoryHandle, _) ->
                use directoryHandle = directoryHandle
                let fileName = ownerDigest ownerId + ".json"
                let descriptor = nativeOpenAt(directoryHandle.DangerousGetHandle().ToInt32(), fileName, openReadOnlyFlags, 0)
                if descriptor < 0 then
                    let errorCode = Marshal.GetLastPInvokeError()
                    if errorCode = 2 then None else fail "cannot safely open Users ownership journal"
                else
                    let handle = new SafeFileHandle(nativeint descriptor, true)
                    try
                        let metadata = inspectDescriptor descriptor
                        if metadata.FileType <> regularType then fail "Users ownership journal is not a regular file"
                        validateSecureRegularFile environment metadata "Users ownership journal"
                        use stream = new FileStream(handle, FileAccess.Read)
                        use reader = new StreamReader(stream, strictUtf8, false)
                        let text = reader.ReadToEnd()
                        if text.Length > maximumJournalBytes then fail "Users ownership journal exceeds its size limit"
                        try
                            let node = JsonNode.Parse(text).AsObject()
                            Some(parseJournal ownerId node)
                        with
                        | :? BackendError -> reraise ()
                        | _ -> fail "Users ownership journal is malformed"
                    with _ ->
                        if not handle.IsClosed then handle.Dispose()
                        reraise ()

    let private persistJournal (environment: HostEnvironment) (journal: Journal) : unit =
        match ensureStateDirectory environment false with
        | None -> fail "Users ownership directory is missing"
        | Some directory ->
            let absoluteFile = actualPath environment (journalPath journal.OwnerId)
            match inspectPath absoluteFile with
            | Some value ->
                if value.FileType <> regularType then fail "refusing to replace a non-regular Users ownership journal"
                validateSecureRegularFile environment value "Users ownership journal"
            | None -> ()
            let bytes = strictUtf8.GetBytes((journalNode journal).ToJsonString(JsonSerializerOptions(WriteIndented = false)))
            let destination = Path.Combine(directory, ownerDigest journal.OwnerId + ".json")
            try
                HostFiles.atomicWrite destination bytes (UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
            with
            | :? BackendError -> reraise ()
            | _ -> fail "cannot safely persist Users ownership journal"

    let private removeJournal (environment: HostEnvironment) (ownerId: string) : unit =
        match openDirectoryChain environment ownerDirectory false 0o700 None with
        | None -> ()
        | Some(directoryHandle, metadata) ->
            use directoryHandle = directoryHandle
            validateSecureOwner environment metadata "Users ownership directory"
            let fileName = ownerDigest ownerId + ".json"
            match inspectAt (directoryHandle.DangerousGetHandle().ToInt32()) fileName with
            | None -> ()
            | Some fileMetadata ->
                if fileMetadata.FileType <> regularType then fail "refusing to remove a non-regular Users ownership journal"
                validateSecureRegularFile environment fileMetadata "Users ownership journal"
                if nativeUnlinkAt(directoryHandle.DangerousGetHandle().ToInt32(), fileName, 0) <> 0 then fail "cannot remove Users ownership journal"
                if nativeFsync(directoryHandle.DangerousGetHandle().ToInt32()) <> 0 then fail "cannot synchronize Users ownership directory"


    let private runCommand (environment: HostEnvironment) (program: string) (arguments: string list) (standardInput: string option) =
        let result =
            try environment.Run program arguments standardInput
            with _ -> fail ("cannot run host command " + program)
        result

    let private runRequired (environment: HostEnvironment) (program: string) (arguments: string list) (standardInput: string option) : CommandResult =
        let result = runCommand environment program arguments standardInput
        if result.ExitCode <> 0 then fail (program + " failed (exit status " + result.ExitCode.ToString(CultureInfo.InvariantCulture) + ")")
        result

    let private parseNssPasswd (text: string) : string * int * int =
        let lines = text.Split([| '\n' |], StringSplitOptions.RemoveEmptyEntries)
        if lines.Length <> 1 then fail "NSS returned an ambiguous account identity"
        let fields = lines[0].TrimEnd('\r').Split(':')
        if fields.Length <> 7 then fail "NSS returned a malformed account identity"
        let uid = parseInteger fields[2] |> Option.defaultWith (fun () -> fail "NSS returned an invalid account UID")
        let gid = parseInteger fields[3] |> Option.defaultWith (fun () -> fail "NSS returned an invalid account GID")
        fields[0], uid, gid

    let private parseNssGroup (text: string) : string * int =
        let lines = text.Split([| '\n' |], StringSplitOptions.RemoveEmptyEntries)
        if lines.Length <> 1 then fail "NSS returned an ambiguous group identity"
        let fields = lines[0].TrimEnd('\r').Split(':')
        if fields.Length <> 4 then fail "NSS returned a malformed group identity"
        let gid = parseInteger fields[2] |> Option.defaultWith (fun () -> fail "NSS returned an invalid group GID")
        fields[0], gid

    let private lookupNss (environment: HostEnvironment) (database: string) (selector: string) : string option =
        let result = runCommand environment "getent" [ database; selector ] None
        if result.ExitCode = 0 then Some result.Stdout
        elif result.ExitCode = 2 then None
        else fail ("getent " + database + " failed (exit status " + result.ExitCode.ToString(CultureInfo.InvariantCulture) + ")")

    let private ensureNssUserMatches (environment: HostEnvironment) (state: LocalState) (name: string) : (int * int) option =
        match lookupNss environment "passwd" name with
        | None ->
            if Map.containsKey name state.Users then fail "local account is not available through NSS"
            None
        | Some text ->
            let resolvedName, uid, gid = parseNssPasswd text
            if resolvedName <> name then fail "NSS returned a different account name"
            match Map.tryFind name state.Users with
            | Some local when local.Uid <> uid || local.Gid <> gid -> fail "local account conflicts with NSS identity"
            | None -> fail "NSS-only accounts cannot be adopted or mutated as local identities"
            | _ -> ()
            match Map.toSeq state.Users |> Seq.tryFind (fun (otherName, user) -> otherName <> name && user.Uid = uid) with
            | Some _ -> fail "local account UID conflicts with another local identity"
            | None -> ()
            match lookupNss environment "passwd" (uid.ToString(CultureInfo.InvariantCulture)) with
            | Some byUid ->
                let uidName, resolvedUid, _ = parseNssPasswd byUid
                if uidName <> name || resolvedUid <> uid then fail "numeric UID conflicts with an NSS identity"
            | None -> fail "NSS cannot resolve the local account UID"
            Some(uid, gid)

    let private ensureNssGroupMatches (environment: HostEnvironment) (state: LocalState) (name: string) : int option =
        match lookupNss environment "group" name with
        | None ->
            if Map.containsKey name state.Groups then fail "local group is not available through NSS"
            None
        | Some text ->
            let resolvedName, gid = parseNssGroup text
            if resolvedName <> name then fail "NSS returned a different group name"
            match Map.tryFind name state.Groups with
            | Some local when local.Gid <> gid -> fail "local group conflicts with NSS identity"
            | None -> fail "NSS-only groups cannot be adopted or mutated as local identities"
            | _ -> ()
            match Map.toSeq state.Groups |> Seq.tryFind (fun (otherName, group) -> otherName <> name && group.Gid = gid) with
            | Some _ -> fail "local group GID conflicts with another local identity"
            | None -> ()
            match lookupNss environment "group" (gid.ToString(CultureInfo.InvariantCulture)) with
            | Some byGid ->
                let gidName, resolvedGid = parseNssGroup byGid
                if gidName <> name || resolvedGid <> gid then fail "numeric GID conflicts with an NSS identity"
            | None -> fail "NSS cannot resolve the local group GID"
            Some gid

    let private connectionIdentity (environment: HostEnvironment) (state: LocalState) (connectionUser: string) : (int * int * Set<int>) option =
        match lookupNss environment "passwd" connectionUser with
        | Some text ->
            let name, uid, gid = parseNssPasswd text
            if name <> connectionUser then fail "NSS returned a different connection user"
            match Map.tryFind connectionUser state.Users with
            | Some local when local.Uid <> uid || local.Gid <> gid -> fail "connection account conflicts with NSS identity"
            | _ -> ()
            let groupsResult = runCommand environment "id" [ "-G"; connectionUser ] None
            if groupsResult.ExitCode <> 0 then fail "cannot determine connection user groups"
            let groupIds =
                groupsResult.Stdout.Split([| ' '; '\t'; '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
                |> Array.map (fun value -> parseInteger value |> Option.defaultWith (fun () -> fail "id returned an invalid connection group"))
                |> Set.ofArray
            Some(uid, gid, groupIds)
        | None -> fail "cannot resolve the connection user through NSS"

    let private ensureConnectionTransport (environment: HostEnvironment) (state: LocalState) (connectionUser: string) : unit =
        let home = Map.tryFind connectionUser state.Users |> Option.map (fun user -> user.Home) |> Option.defaultValue "/"
        let arguments =
            [ "--user"
              connectionUser
              "--"
              "/usr/bin/env"
              "-i"
              "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
              "USER=" + connectionUser
              "LOGNAME=" + connectionUser
              "HOME=" + home
              "LC_ALL=C"
              "/usr/bin/sudo"
              "-k"
              "-n"
              "--"
              "sh"
              "-c"
              "test \"$(/usr/bin/id -u)\" = 0" ]
        runRequired environment "runuser" arguments None |> ignore
    let private readSubordinateRanges (environment: HostEnvironment) (logicalPath: string) : Map<string, Set<IdRange>> =
        match readOptionalTextFile environment logicalPath with
        | None -> Map.empty
        | Some text ->
            text.Split([| '\n' |], StringSplitOptions.RemoveEmptyEntries)
            |> Array.map (fun line ->
                let fields = line.TrimEnd('\r').Split(':')
                if fields.Length <> 3 then fail ("host file " + logicalPath + " contains a malformed range")
                let start = parseInteger fields[1] |> Option.defaultWith (fun () -> fail "subordinate ID file contains an invalid start")
                let count = parseInteger fields[2] |> Option.defaultWith (fun () -> fail "subordinate ID file contains an invalid count")
                if start <= 0 || count <= 0 || uint64 start + uint64 count - 1UL > uint64 UInt32.MaxValue then fail "subordinate ID file contains an invalid range"
                fields[0], { Start = uint32 start; Count = uint32 count })
            |> Array.groupBy fst
            |> Array.map (fun (name, entries) -> name, entries |> Array.map snd |> Set.ofArray)
            |> Map.ofArray

    let private validateSubordinateRanges (description: string) (userName: string) (current: Map<string, Set<IdRange>>) (requested: IdRange list) =
        for range in requested do
            for KeyValue(ownerName, ownerRanges) in current do
                for currentRange in ownerRanges do
                    if rangesOverlap range currentRange && (ownerName <> userName || range <> currentRange) then
                        fail (description + " overlaps an existing subordinate ID range")
    let private getIdBounds (bounds: IdBounds) (kind: string) (isUser: bool) : int * int =
        match kind, isUser with
        | "system", true -> bounds.SystemUserMinimum, bounds.SystemUserMaximum
        | "system", false -> bounds.SystemGroupMinimum, bounds.SystemGroupMaximum
        | _, true -> bounds.UserMinimum, bounds.UserMaximum
        | _, false -> bounds.GroupMinimum, bounds.GroupMaximum

    let private validateId (bounds: IdBounds) (kind: string) (isUser: bool) (value: int) : unit =
        if value <= 0 then fail "UID and GID zero are reserved"
        let minimum, maximum = getIdBounds bounds kind isUser
        if value < minimum || value > maximum then fail "requested UID or GID is outside the configured account range"

    let private allocateId (bounds: IdBounds) (kind: string) (isUser: bool) (used: Set<int>) (preferred: int option) : int =
        let minimum, maximum = getIdBounds bounds kind isUser
        let reserved = if isUser then bounds.ReservedUserIds else bounds.ReservedGroupIds
        let used = Set.union used reserved
        let available value = value >= minimum && value <= maximum && not (Set.contains value used)
        match preferred with
        | Some value when available value -> value
        | Some _ -> fail "requested UID or GID is already in use"
        | None ->
            [ minimum .. maximum ]
            |> List.tryFind available
            |> Option.defaultWith (fun () -> fail "no free UID or GID remains in the configured range")

    let private groupMemberships (state: LocalState) (userName: string) : Set<string> =
        state.Groups
        |> Map.toSeq
        |> Seq.choose (fun (name, group) -> if Set.contains userName group.Members then Some name else None)
        |> Set.ofSeq

    let private primaryGroupName (state: LocalState) (gid: int) : string option =
        state.Groups |> Map.toSeq |> Seq.tryPick (fun (name, group) -> if group.Gid = gid then Some name else None)

    let private kindForId (bounds: IdBounds) (isUser: bool) (id: int) : string =
        let systemMinimum, systemMaximum = getIdBounds bounds "system" isUser
        if id >= systemMinimum && id <= systemMaximum then "system" else "human"

    let private rangeJson (ranges: Set<IdRange>) = rangesNode ranges

    let private accountExpiryNode (expiryDay: int64 option) : JsonNode =
        match expiryDay with
        | None -> null
        | Some days ->
            let date = DateOnly.FromDateTime(DateTime.UnixEpoch.AddDays(float days))
            let value = JsonObject()
            value["kind"] <- jsonString "on"
            value["date"] <- jsonString(date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture))
            value :> JsonNode

    let private policyNode (shadow: ShadowAccount option) : JsonNode =
        let value = JsonObject()
        let put (name: string) (field: int option) : unit = value[name] <- field |> Option.map jsonInt |> Option.defaultValue null
        match shadow with
        | Some current ->
            put "minDays" current.MinimumDays
            put "maxDays" current.MaximumDays
            put "warnDays" current.WarningDays
            put "inactiveDays" current.InactiveDays
        | None ->
            put "minDays" None
            put "maxDays" None
            put "warnDays" None
            put "inactiveDays" None
        value :> JsonNode

    let private accountKeys (environment: HostEnvironment) (account: UserAccount) : string list =
        if account.Home = "/nonexistent" || String.IsNullOrWhiteSpace account.Home then []
        else
            let uid = uint32 account.Uid
            let homePath = account.Home
            match openDirectoryChain environment homePath false 0o700 (Some uid) with
            | None -> []
            | Some(homeHandle, homeMetadata) ->
                use homeHandle = homeHandle
                if homeMetadata.UserId <> uid || (homeMetadata.Mode &&& 0o022) <> 0 then fail "account home directory ownership or permissions are unsafe"
                match createOrOpenSshDirectory environment account.Name homePath uid false with
                | None -> []
                | Some(sshHandle, _) ->
                    use sshHandle = sshHandle
                    match safeFileContentsAt (sshHandle.DangerousGetHandle().ToInt32()) "authorized_keys" uid with
                    | None -> []
                    | Some text -> text.Split([| '\n' |], StringSplitOptions.RemoveEmptyEntries) |> Array.map (fun line -> line.TrimEnd('\r')) |> Array.toList

    let private actualGroupNode (bounds: IdBounds) (state: LocalState) (desiredName: string) (desiredKind: string option) : JsonObject =
        let result = JsonObject()
        result["name"] <- jsonString desiredName
        match Map.tryFind desiredName state.Groups with
        | None ->
            result["exists"] <- jsonBool false
            result["gid"] <- null
            result["kind"] <- desiredKind |> Option.map jsonString |> Option.defaultValue null
            result["state"] <- jsonString "absent"
            result["members"] <- JsonArray()
        | Some group ->
            result["exists"] <- jsonBool true
            result["gid"] <- jsonInt group.Gid
            result["kind"] <- jsonString(defaultArg desiredKind (kindForId bounds false group.Gid))
            result["state"] <- jsonString "present"
            result["members"] <- stringsNode group.Members
        result

    let private actualUserNode (environment: HostEnvironment) (state: LocalState) (subordinateUids: Map<string, Set<IdRange>>) (subordinateGids: Map<string, Set<IdRange>>) (desiredName: string) : JsonObject =
        let result = JsonObject()
        result["name"] <- jsonString desiredName
        match Map.tryFind desiredName state.Users with
        | None ->
            result["exists"] <- jsonBool false
            result["uid"] <- null
            result["gid"] <- null
            result["description"] <- null
            result["home"] <- null
            result["shell"] <- null
            result["locked"] <- null
            result["accountExpiry"] <- null
            result["passwordPolicy"] <- policyNode None
            result["supplementaryGroups"] <- JsonArray()
            result["subordinateUids"] <- rangesNode Set.empty
            result["subordinateGids"] <- rangesNode Set.empty
            result["authorizedKeys"] <- JsonArray()
        | Some user ->
            let shadow = Map.tryFind desiredName state.Shadows
            result["exists"] <- jsonBool true
            result["uid"] <- jsonInt user.Uid
            result["gid"] <- jsonInt user.Gid
            result["description"] <- jsonString user.Description
            result["home"] <- jsonString user.Home
            result["shell"] <- jsonString user.Shell
            result["locked"] <- jsonBool(shadow |> Option.exists (fun value -> value.PasswordHash.StartsWith("!", StringComparison.Ordinal) || value.PasswordHash.StartsWith("*", StringComparison.Ordinal)))
            result["accountExpiry"] <- shadow |> Option.bind (fun value -> value.ExpiryDay) |> accountExpiryNode
            result["passwordPolicy"] <- policyNode shadow
            result["supplementaryGroups"] <- stringsNode (groupMemberships state desiredName)
            result["subordinateUids"] <- rangesNode (Map.tryFind desiredName subordinateUids |> Option.defaultValue Set.empty)
            result["subordinateGids"] <- rangesNode (Map.tryFind desiredName subordinateGids |> Option.defaultValue Set.empty)
            result["authorizedKeys"] <- stringsNode (accountKeys environment user)
        result

    let private envelope (exists: bool) (inSync: bool) (actual: JsonObject) : JsonNode =
        let result = JsonObject()
        result["exists"] <- jsonBool exists
        result["inSync"] <- jsonBool inSync
        result["actual"] <- actual
        result :> JsonNode

    let private renderOptionValue (value: string) : string =
        let builder = StringBuilder(value.Length + 2)
        builder.Append('"') |> ignore
        for character in value do
            if character = '\\' || character = '"' then builder.Append('\\') |> ignore
            builder.Append(character) |> ignore
        builder.Append('"').ToString()

    let private renderKey (key: KeySpec) : string =
        let options = ResizeArray<string>()
        if key.Restrict then options.Add("restrict")
        let addAllow option enabled =
            match enabled with
            | Some true -> options.Add(option)
            | Some false -> options.Add("no-" + option)
            | None -> ()
        addAllow "pty" key.AllowPty
        addAllow "agent-forwarding" key.AllowAgentForwarding
        addAllow "port-forwarding" key.AllowPortForwarding
        addAllow "X11-forwarding" key.AllowX11Forwarding
        addAllow "user-rc" key.AllowUserRc
        if not key.AllowFrom.IsEmpty then options.Add("from=" + renderOptionValue(String.Join(",", key.AllowFrom)))
        match key.Command with Some value -> options.Add("command=" + renderOptionValue value) | None -> ()
        match key.Expires with Some value -> options.Add("expiry-time=" + renderOptionValue(value.UtcDateTime.ToString("yyyyMMddHHmmss'Z'", CultureInfo.InvariantCulture))) | None -> ()
        for endpoint in key.PermitOpen do options.Add("permitopen=" + renderOptionValue endpoint)
        for endpoint in key.PermitListen do options.Add("permitlisten=" + renderOptionValue endpoint)
        if key.VerifyRequired then options.Add("verify-required")
        let optionsText = if options.Count = 0 then "" else String.Join(",", options) + " "
        let comment = key.Comment |> Option.map (fun value -> " " + value) |> Option.defaultValue ""
        optionsText + key.KeyType + " " + key.KeyData + comment

    let private validateSafeLogicalTarget (path: string) : string =
        if String.IsNullOrWhiteSpace path || not (Path.IsPathRooted path) || hasControl path then fail "path must be absolute and safe"
        let normalized = try Path.GetFullPath path with _ -> fail "path is invalid"
        if normalized <> path || normalized = Path.GetPathRoot normalized then fail "path must be a canonical non-root path"
        path

    let private setHomeMode (environment: HostEnvironment) (user: UserAccount) (mode: int) : unit =
        if mode < 0 || mode > 0o777 then fail "home mode must be between 0000 and 0777"
        match openDirectoryChain environment user.Home false 0o700 (Some(uint32 user.Uid)) with
        | None -> fail "account home directory does not exist"
        | Some(handle, metadata) ->
            use handle = handle
            if metadata.FileType <> directoryType || metadata.UserId <> uint32 user.Uid then fail "refusing to change an unowned account home directory"
            if nativeFchmod(handle.DangerousGetHandle().ToInt32(), mode) <> 0 then fail "cannot set account home permissions"

    let private copyHomeSkeleton (environment: HostEnvironment) (user: UserAccount) (skeletonPath: string) (destination: string) : unit =
        match openDirectoryChain environment skeletonPath false 0o700 None with
        | None -> fail "home skeleton directory does not exist"
        | Some(handle, metadata) ->
            use handle = handle
            validateDirectoryMetadata environment false metadata
        runRequired
            environment
            "runuser"
            [ "--user"
              user.Name
              "--"
              "cp"
              "--archive"
              "--no-preserve=ownership"
              "--"
              Path.Combine(actualPath environment skeletonPath, ".")
              Path.Combine(actualPath environment destination, ".") ]
            None
        |> ignore

    let private ensureHomeForExisting (environment: HostEnvironment) (home: HomeSpec) (user: UserAccount) : unit =
        match home.Kind, home.Path with
        | "none", None ->
            if user.Home <> "/nonexistent" then fail "changing an existing account home is not supported"
        | ("create" | "existing"), Some path ->
            if user.Home <> path then fail "moving an existing account home is not supported"
            let mode = defaultArg home.Mode 0o700
            match openDirectoryChain environment path false 0o700 (Some(uint32 user.Uid)) with
            | Some(handle, metadata) ->
                use handle = handle
                if metadata.FileType <> directoryType || metadata.UserId <> uint32 user.Uid then fail "account home directory is not owned by the account"
                if home.Kind = "existing" && home.Skeleton.IsSome then fail "a skeleton may only be applied while creating a missing home"
                match home.Mode with
                | Some requestedMode when metadata.Mode <> requestedMode ->
                    if nativeFchmod(handle.DangerousGetHandle().ToInt32(), requestedMode) <> 0 then fail "cannot set account home permissions"
                | _ -> ()
            | None when home.Kind = "existing" -> fail "requested existing home directory does not exist"
            | None ->
                let parent = Path.GetDirectoryName path
                let name = Path.GetFileName path
                match openDirectoryChain environment parent false 0o700 None with
                | None -> fail "account home parent directory does not exist"
                | Some(parentHandle, _) ->
                    use parentHandle = parentHandle
                    if nativeMkdirAt(parentHandle.DangerousGetHandle().ToInt32(), name, mode) <> 0 then fail "cannot create account home directory"
                    let homeFd = nativeOpenAt(parentHandle.DangerousGetHandle().ToInt32(), name, openDirectoryFlags, 0)
                    if homeFd < 0 then fail "cannot safely open created account home directory"
                    use homeHandle = new SafeFileHandle(nativeint homeFd, true)
                    if nativeFchown(homeFd, uint32 user.Uid, uint32 user.Gid) <> 0 then fail "cannot set account home ownership"
                    if nativeFchmod(homeFd, mode) <> 0 then fail "cannot set account home permissions"
                    match home.Skeleton with
                    | Some skeleton -> copyHomeSkeleton environment user skeleton path
                    | None -> ()
        | _ -> fail "invalid home specification"

    let private createHomeForNew (environment: HostEnvironment) (home: HomeSpec) (uid: int) : string * bool * string option =
        match home.Kind, home.Path with
        | "none", None -> "/nonexistent", false, None
        | "create", Some path ->
            let path = validateSafeLogicalTarget path
            if inspectPath (actualPath environment path) |> Option.isSome then fail "requested new account home already exists"
            match home.Skeleton with
            | Some skeleton ->
                match openDirectoryChain environment skeleton false 0o700 None with
                | Some(handle, metadata) ->
                    use handle = handle
                    validateDirectoryMetadata environment false metadata
                | None -> fail "home skeleton directory does not exist"
            | None -> ()
            let parent = Path.GetDirectoryName path
            match openDirectoryChain environment parent false 0o700 None with
            | None -> fail "new account home parent directory does not exist"
            | Some(parentHandle, _) ->
                use parentHandle = parentHandle
                path, true, home.Skeleton
        | "existing", Some path ->
            let path = validateSafeLogicalTarget path
            match openDirectoryChain environment path false 0o700 (Some(uint32 uid)) with
            | None -> fail "requested existing home directory does not exist"
            | Some(handle, metadata) ->
                use handle = handle
                if metadata.UserId <> uint32 uid then fail "requested existing home is not owned by the new account"
                path, false, None
        | _ -> fail "invalid home specification"

    let private hashDigest (hash: string) =
        SHA256.HashData(strictUtf8.GetBytes hash) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()

    let private getUserState (journal: Journal) (name: string) : UserOwnership =
        Map.tryFind name journal.Users
        |> Option.defaultValue
            { Uid = 0
              Gid = 0
              Identity = ""
              CreationComplete = true
              CreationHomeKind = None
              CreationHomePath = None
              CreationHomeMode = None
              CreationHomeSkeleton = None
              CreationShell = None
              MembershipsAdded = Set.empty
              KeyMode = None
              KeyHome = None
              KeyLines = []
              KeyPendingBefore = None
              KeyPendingAfter = None
              KeyPendingDesired = None
              KeyPendingMode = None
              KeyPendingHome = None
              KeyPendingAdded = Set.empty
              KeysAdded = Set.empty
              SubordinateUidsAdded = Set.empty
              SubordinateGidsAdded = Set.empty
              PasswordKind = None
              PasswordDigest = None }

    let private persistUpdatedUser (environment: HostEnvironment) (journal: Journal) (name: string) (record: UserOwnership) : Journal =
        let updated = withUserUserRecord journal name record
        persistJournal environment updated
        updated

    let private persistUpdatedGroup (environment: HostEnvironment) (journal: Journal) (name: string) (record: GroupOwnership) : Journal =
        let updated = withGroupRecord journal name record
        persistJournal environment updated
        updated

    let private verifyJournalIdentities (environment: HostEnvironment) (state: LocalState) (journal: Journal) : unit =
        for KeyValue(name, record) in journal.Users do
            match Map.tryFind name state.Users with
            | Some user when user.Uid <> record.Uid || user.Gid <> record.Gid -> fail "owned user name was reused by a different numeric identity"
            | Some _ -> ()
            | None ->
                if state.Users |> Map.exists (fun _ user -> user.Uid = record.Uid) then fail "owned UID was reused by another local identity"
                if (lookupNss environment "passwd" name).IsSome then fail "an NSS account conflicts with a missing owned local account"
                if (lookupNss environment "passwd" (record.Uid.ToString(CultureInfo.InvariantCulture))).IsSome then fail "owned UID was reused by an NSS identity"
        for KeyValue(name, record) in journal.Groups do
            match Map.tryFind name state.Groups with
            | Some group when group.Gid <> record.Gid -> fail "owned group name was reused by a different numeric identity"
            | Some _ -> ()
            | None ->
                if state.Groups |> Map.exists (fun _ group -> group.Gid = record.Gid) then fail "owned GID was reused by another local group"
                if (lookupNss environment "group" name).IsSome then fail "an NSS group conflicts with a missing owned local group"
                if (lookupNss environment "group" (record.Gid.ToString(CultureInfo.InvariantCulture))).IsSome then fail "owned GID was reused by an NSS group"

    let private validateOwnerConflicts (environment: HostEnvironment) (ownerId: string) (journal: Journal) (requestedGroups: string list) (requestedUsers: string list) : Set<int> * Set<int> =
        let mutable reservedUserIds = Set.empty
        let mutable reservedGroupIds = Set.empty
        let directory = actualPath environment ownerDirectory
        if Directory.Exists directory then
            for file in Directory.EnumerateFiles(directory, "*.json", SearchOption.TopDirectoryOnly) do
                match inspectPath file with
                | Some metadata -> validateSecureRegularFile environment metadata "Users ownership journal"
                | None -> fail "Users ownership journal disappeared during ownership scan"
                let text =
                    try File.ReadAllText(file, strictUtf8)
                    with _ -> fail "cannot read Users ownership journal during ownership scan"
                if text.Length > maximumJournalBytes then fail "Users ownership journal exceeds its size limit"
                let other =
                    try JsonNode.Parse(text).AsObject()
                    with _ -> fail "Users ownership journal is malformed"
                let otherOwner = other["ownerId"].GetValue<string>()
                if otherOwner <> ownerId then
                    let otherGroups = other["groups"].AsObject()
                    let otherUsers = other["users"].AsObject()
                    for KeyValue(_, userNode) in otherUsers do
                        let userRecord = userNode.AsObject()
                        reservedUserIds <- Set.add (userRecord["uid"].GetValue<int>()) reservedUserIds
                    for KeyValue(_, groupNode) in otherGroups do
                        let groupRecord = groupNode.AsObject()
                        reservedGroupIds <- Set.add (groupRecord["gid"].GetValue<int>()) reservedGroupIds
                    for name in requestedGroups do
                        if otherGroups.ContainsKey(name) || otherUsers.ContainsKey(name) then fail "identity is already owned by another Users resource"
                    for name in requestedUsers do
                        if otherUsers.ContainsKey(name) || otherGroups.ContainsKey(name) then fail "identity is already owned by another Users resource"
                    for name in journal.Groups.Keys do
                        if otherGroups.ContainsKey(name) || otherUsers.ContainsKey(name) then fail "identity is already owned by another Users resource"
                    for name in journal.Users.Keys do
                        if otherUsers.ContainsKey(name) || otherGroups.ContainsKey(name) then fail "identity is already owned by another Users resource"
        reservedUserIds, reservedGroupIds

    let private ensureUserEntry (state: LocalState) (name: string) : UserAccount =
        Map.tryFind name state.Users |> Option.defaultWith (fun () -> fail "local user does not exist")

    let private ensureGroupEntry (state: LocalState) (name: string) : GroupAccount =
        Map.tryFind name state.Groups |> Option.defaultWith (fun () -> fail "local group does not exist")

    let private executeGroupAdd (environment: HostEnvironment) (kind: string) (gid: int) (name: string) : unit =
        let args = ResizeArray<string>()
        if kind = "system" then args.Add("--system")
        args.Add("--gid")
        args.Add(gid.ToString(CultureInfo.InvariantCulture))
        args.Add("--")
        args.Add(name)
        runRequired environment "groupadd" (List.ofSeq args) None |> ignore


    let private makeGroupRecord (gid: int) (identity: string) (kind: string option) : GroupOwnership =
        { Gid = gid; Identity = identity; Kind = kind }

    let private makeUserRecord (uid: int) (gid: int) (identity: string) : UserOwnership =
        { Uid = uid
          Gid = gid
          Identity = identity
          CreationComplete = identity <> "created"
          CreationHomeKind = None
          CreationHomePath = None
          CreationHomeMode = None
          CreationHomeSkeleton = None
          CreationShell = None
          MembershipsAdded = Set.empty
          KeyMode = None
          KeyHome = None
          KeyLines = []
          KeyPendingBefore = None
          KeyPendingAfter = None
          KeyPendingDesired = None
          KeyPendingMode = None
          KeyPendingHome = None
          KeyPendingAdded = Set.empty
          KeysAdded = Set.empty
          SubordinateUidsAdded = Set.empty
          SubordinateGidsAdded = Set.empty
          PasswordKind = None
          PasswordDigest = None }

    let private hasPendingKeys (record: UserOwnership) : bool =
        record.KeyPendingBefore.IsSome
        || record.KeyPendingAfter.IsSome
        || record.KeyPendingDesired.IsSome
        || record.KeyPendingMode.IsSome
        || record.KeyPendingHome.IsSome
        || not record.KeyPendingAdded.IsEmpty

    let private clearPendingKeys (record: UserOwnership) : UserOwnership =
        { record with
            KeyPendingBefore = None
            KeyPendingAfter = None
            KeyPendingDesired = None
            KeyPendingMode = None
            KeyPendingHome = None
            KeyPendingAdded = Set.empty }

    let private commitPendingKeys (record: UserOwnership) : UserOwnership =
        match record.KeyPendingAfter, record.KeyPendingDesired, record.KeyPendingMode, record.KeyPendingHome with
        | Some after, Some desired, Some mode, Some home ->
            let added = if mode = "managed" then record.KeyPendingAdded |> Set.intersect (Set.ofList desired) else Set.empty
            { record with
                KeyMode = Some mode
                KeyHome = Some home
                KeyLines = after
                KeysAdded = added }
            |> clearPendingKeys
        | _ -> fail "Users key ownership journal contains an incomplete pending intent"

    let private makeKeyIntent (record: UserOwnership) (mode: string) (home: string) (desired: string list) (added: Set<string>) (before: string list) (after: string list) : UserOwnership =
        { record with
            KeyPendingBefore = Some before
            KeyPendingAfter = Some after
            KeyPendingDesired = Some desired
            KeyPendingMode = Some mode
            KeyPendingHome = Some home
            KeyPendingAdded = added }

    let private createOrAdoptDeclaredGroup (environment: HostEnvironment) (bounds: IdBounds) (state: LocalState) (journal: Journal) (spec: GroupSpec) : LocalState * Journal =
        if spec.State = "absent" then state, journal
        else
            match Map.tryFind spec.Name state.Groups with
            | Some group ->
                let prior = Map.tryFind spec.Name journal.Groups
                if prior.IsNone && spec.Existing <> "adopt" then fail "existing unowned group was rejected; request existing=adopt"
                let nssGid = ensureNssGroupMatches environment state spec.Name |> Option.defaultWith (fun () -> fail "local group is unavailable through NSS")
                if nssGid <> group.Gid then fail "local group conflicts with NSS identity"
                match prior with Some owned when owned.Gid <> group.Gid -> fail "owned group numeric identity changed" | _ -> ()
                match spec.Gid with Some value when value <> group.Gid -> fail "changing an existing group GID is not supported" | _ -> ()
                if spec.Kind.IsSome then
                    let kind = defaultArg spec.Kind "human"
                    let lower, upper = getIdBounds bounds kind false
                    if group.Gid < lower || group.Gid > upper then fail "existing group GID does not match its declared kind"
                let updated = persistUpdatedGroup environment journal spec.Name (makeGroupRecord group.Gid (if prior.IsSome then prior.Value.Identity else "adopted") (spec.Kind |> Option.orElse (prior |> Option.bind (fun value -> value.Kind))))
                state, updated
            | None ->
                let prior = Map.tryFind spec.Name journal.Groups
                let kind =
                    match spec.Kind, prior with
                    | Some value, _ -> value
                    | None, Some value -> defaultArg value.Kind "human"
                    | None, None -> "human"
                let preferredGid =
                    match prior with
                    | Some value when value.Identity = "created" ->
                        match spec.Gid with Some requested when requested <> value.Gid -> fail "changing an owned group GID is not supported" | _ -> Some value.Gid
                    | Some _ -> fail "an adopted group disappeared; refusing to recreate it"
                    | None when spec.Existing = "adopt" -> fail "cannot adopt a group that does not exist"
                    | None -> spec.Gid
                let used = state.Groups |> Map.toSeq |> Seq.map (snd >> fun value -> value.Gid) |> Set.ofSeq
                let gid = allocateId bounds kind false used preferredGid
                match lookupNss environment "group" (gid.ToString(CultureInfo.InvariantCulture)) with
                | Some _ -> fail "requested GID is already assigned by NSS"
                | None -> ()
                let intent = persistUpdatedGroup environment journal spec.Name (makeGroupRecord gid "created" (Some kind))
                executeGroupAdd environment kind gid spec.Name
                let refreshed = parseLocalState environment
                let created = Map.tryFind spec.Name refreshed.Groups |> Option.defaultWith (fun () -> fail "groupadd did not create the requested local group")
                if created.Gid <> gid then fail "groupadd created an unexpected numeric group identity"
                ensureNssGroupMatches environment refreshed spec.Name |> ignore
                refreshed, intent

    let private createPrivateGroup (environment: HostEnvironment) (bounds: IdBounds) (state: LocalState) (journal: Journal) (userName: string) (kind: string) (preferredGid: int option) : int * LocalState * Journal =
        match Map.tryFind userName state.Groups with
        | Some group ->
            let owned = Map.tryFind userName journal.Groups
            match owned with
            | Some record when record.Gid = group.Gid -> group.Gid, state, journal
            | _ -> fail "private primary group already exists and is not owned by this Users resource"
        | None ->
            let prior = Map.tryFind userName journal.Groups
            let preferred, effectiveKind =
                match prior with
                | Some record when record.Identity = "created" -> Some record.Gid, defaultArg record.Kind kind
                | Some _ -> fail "an adopted private group disappeared; refusing to recreate it"
                | None -> preferredGid, kind
            let used = state.Groups |> Map.toSeq |> Seq.map (snd >> fun value -> value.Gid) |> Set.ofSeq
            let gid = allocateId bounds effectiveKind false used preferred
            match lookupNss environment "group" (gid.ToString(CultureInfo.InvariantCulture)) with
            | Some _ -> fail "private group GID is already assigned by NSS"
            | None -> ()
            let intent = persistUpdatedGroup environment journal userName (makeGroupRecord gid "created" (Some effectiveKind))
            executeGroupAdd environment effectiveKind gid userName
            let refreshed = parseLocalState environment
            let group = Map.tryFind userName refreshed.Groups |> Option.defaultWith (fun () -> fail "groupadd did not create a private primary group")
            if group.Gid <> gid then fail "groupadd created an unexpected private group identity"
            gid, refreshed, intent


    let private runUsermod (environment: HostEnvironment) (userName: string) (options: string list) : unit =
        runRequired environment "usermod" (options @ [ "--"; userName ]) None |> ignore

    let private userIsConnectionUser (connectionUid: int option) (connectionName: string option) (user: UserAccount) : bool =
        (connectionName |> Option.exists ((=) user.Name))
        || (connectionUid |> Option.exists (fun value -> value = user.Uid))

    let private validateHomeNotSystemPath (path: string) : unit =
        let protectedRoots = [ "/"; "/etc"; "/usr"; "/bin"; "/sbin"; "/lib"; "/lib64"; "/proc"; "/sys"; "/dev"; "/run"; "/boot" ]
        if protectedRoots |> List.exists (fun root -> path = root || path.StartsWith(root + "/", StringComparison.Ordinal)) then fail "account home cannot be located in a system directory"

    let private createNewUser (environment: HostEnvironment) (bounds: IdBounds) (state: LocalState) (journal: Journal) (spec: UserSpec) (connectionUid: int option) (connectionName: string) : LocalState * Journal =
        let kind = defaultArg spec.Kind "human"
        if Map.containsKey spec.Name state.Users then fail "user already exists"
        let existingNss = lookupNss environment "passwd" spec.Name
        if existingNss.IsSome then fail "an NSS account already uses this name"
        let pendingUser = Map.tryFind spec.Name journal.Users
        let preferredUid =
            match pendingUser with
            | Some owned when owned.Identity = "created" ->
                match spec.Uid with
                | Some requested when requested <> owned.Uid -> fail "changing an owned user UID is not supported"
                | _ -> Some owned.Uid
            | Some _ -> fail "an adopted user disappeared; refusing to recreate it"
            | None -> spec.Uid
        let usedUids = state.Users |> Map.toSeq |> Seq.map (snd >> fun user -> user.Uid) |> Set.ofSeq
        let uid = allocateId bounds kind true usedUids preferredUid
        if spec.Name = connectionName || connectionUid = Some uid then fail "the active connection identity cannot be created or managed"
        let lower, upper = getIdBounds bounds kind true
        if uid < lower || uid > upper then fail "new user UID is outside its configured kind range"
        match lookupNss environment "passwd" (uid.ToString(CultureInfo.InvariantCulture)) with
        | Some _ -> fail "requested UID is already assigned by NSS"
        | None -> ()
        let privatePrimary =
            match spec.PrimaryGroup with
            | Some("existing", Some name) -> name, false
            | Some("private", _) | None -> spec.Name, true
            | _ -> fail "invalid primary group"
        let primaryName, createPrivate = privatePrimary
        let gid, afterGroup, groupJournal =
            if createPrivate then
                let groupMinimum, groupMaximum = getIdBounds bounds kind false
                let usedGids = state.Groups |> Map.toSeq |> Seq.map (snd >> fun group -> group.Gid) |> Set.ofSeq
                let preferred = if uid >= groupMinimum && uid <= groupMaximum && not (Set.contains uid usedGids) then Some uid else None
                createPrivateGroup environment bounds state journal primaryName kind preferred
            else
                let group = ensureGroupEntry state primaryName
                ensureNssGroupMatches environment state primaryName |> ignore
                group.Gid, state, journal
        let usedGids = afterGroup.Groups |> Map.toSeq |> Seq.map (snd >> fun group -> group.Gid) |> Set.ofSeq
        match pendingUser with
        | Some owned when owned.Identity = "created" && owned.Gid <> gid -> fail "changing an owned user primary GID is not supported"
        | _ -> ()
        if Set.contains gid usedGids |> not then fail "primary group disappeared before user creation"
        if gid = 0 then fail "root group cannot be used as a newly managed private group"
        let defaultHome =
            match kind with
            | "system" -> { Kind = "none"; Path = None; Mode = None; Skeleton = None }
            | _ -> { Kind = "create"; Path = Some("/home/" + spec.Name); Mode = Some 0o700; Skeleton = None }
        let home = defaultArg spec.Home defaultHome
        let shell = defaultArg spec.Shell (if kind = "system" then "/usr/sbin/nologin" else "/bin/bash")
        let homePath, createHome, skeleton = createHomeForNew environment home uid
        if home.Kind = "create" then validateHomeNotSystemPath homePath
        let creationHomeMode = if home.Kind = "create" then Some(defaultArg home.Mode 0o700) else home.Mode
        let creationIntent =
            { (makeUserRecord uid gid "created") with
                CreationComplete = false
                CreationHomeKind = Some home.Kind
                CreationHomePath = home.Path
                CreationHomeMode = creationHomeMode
                CreationHomeSkeleton = home.Skeleton
                CreationShell = Some shell }
        let userIntent = persistUpdatedUser environment groupJournal spec.Name creationIntent
        let userAddArgs = ResizeArray<string>()
        if kind = "system" then userAddArgs.Add("--system")
        userAddArgs.Add("--uid")
        userAddArgs.Add(uid.ToString(CultureInfo.InvariantCulture))
        userAddArgs.Add("--gid")
        userAddArgs.Add(gid.ToString(CultureInfo.InvariantCulture))
        match spec.Description with Some value -> userAddArgs.Add("--comment"); userAddArgs.Add(value) | None -> ()
        userAddArgs.Add("--home-dir")
        userAddArgs.Add(homePath)
        if createHome then userAddArgs.Add("--create-home") else userAddArgs.Add("--no-create-home")
        match skeleton with Some value -> userAddArgs.Add("--skel"); userAddArgs.Add(value) | None -> ()
        userAddArgs.Add("--shell")
        userAddArgs.Add(shell)
        userAddArgs.Add("--password")
        userAddArgs.Add("!")
        userAddArgs.Add("--")
        userAddArgs.Add(spec.Name)
        runRequired environment "useradd" (List.ofSeq userAddArgs) None |> ignore
        let refreshed = parseLocalState environment
        let created = ensureUserEntry refreshed spec.Name
        if created.Uid <> uid || created.Gid <> gid then fail "useradd created an unexpected numeric identity"
        if userIsConnectionUser connectionUid (Some connectionName) created then fail "the active connection user cannot be created or managed"
        ensureNssUserMatches environment refreshed spec.Name |> ignore
        match home.Kind, home.Mode with
        | "create", Some mode -> setHomeMode environment created mode
        | "create", None -> setHomeMode environment created 0o700
        | _, Some mode -> setHomeMode environment created mode
        | _ -> ()
        refreshed, userIntent

    let private applyPassword (environment: HostEnvironment) (userName: string) (state: LocalState) (record: UserOwnership) (password: PasswordSpec option) (newlyCreated: bool) : UserOwnership =
        match password with
        | None -> { record with PasswordKind = None; PasswordDigest = None }
        | Some specification ->
            let shadow = Map.tryFind userName state.Shadows |> Option.defaultWith (fun () -> fail "local shadow entry is missing")
            if specification.Kind = "locked" then
                let currentlyLocked = shadow.PasswordHash.StartsWith("!", StringComparison.Ordinal) || shadow.PasswordHash.StartsWith("*", StringComparison.Ordinal)
                if not currentlyLocked then runRequired environment "passwd" [ "--lock"; "--"; userName ] None |> ignore
                { record with PasswordKind = Some "locked"; PasswordDigest = None }
            else
                let hash = specification.Hash |> Option.defaultWith (fun () -> fail "password hash is missing")
                let shouldUpdate = specification.Update = "always" || newlyCreated
                if not shouldUpdate then
                    { record with PasswordKind = Some "onCreate"; PasswordDigest = None }
                else
                    let expected = hashDigest hash
                    let actual = hashDigest shadow.PasswordHash
                    if actual <> expected then
                        let stdin = userName + ":" + hash + "\n"
                        runRequired environment "chpasswd" [ "--encrypted" ] (Some stdin) |> ignore
                    { record with PasswordKind = Some "hash"; PasswordDigest = Some expected }

    let private applyExpiryAndPolicy (environment: HostEnvironment) (userName: string) (expiry: (string * string option) option) (policy: Map<string, int>) : unit =
        let args = ResizeArray<string>()
        match expiry with
        | Some("never", _) -> args.Add("--expiredate"); args.Add("-1")
        | Some("on", Some date) -> args.Add("--expiredate"); args.Add(date)
        | Some _ -> fail "invalid account expiry specification"
        | None -> ()
        for name, option in [ "minDays", "--mindays"; "maxDays", "--maxdays"; "warnDays", "--warndays"; "inactiveDays", "--inactive" ] do
            match Map.tryFind name policy with
            | Some value -> args.Add(option); args.Add(value.ToString(CultureInfo.InvariantCulture))
            | None -> ()
        if args.Count > 0 then
            args.Add("--")
            args.Add(userName)
            runRequired environment "chage" (List.ofSeq args) None |> ignore


    let private applySubordinateSet (environment: HostEnvironment) (userName: string) (previousRanges: Set<IdRange>) (requested: IdRange list option) (logicalPath: string) (addOption: string) (delOption: string) (persistIntent: Set<IdRange> -> unit) : Set<IdRange> =
        let allRanges = readSubordinateRanges environment logicalPath
        let current = Map.tryFind userName allRanges |> Option.defaultValue Set.empty
        let desired = requested |> Option.defaultValue [] |> Set.ofList
        validateSubordinateRanges logicalPath userName allRanges (desired |> Set.toList)
        let additions = desired |> Set.filter (fun range -> not (Set.contains range current))
        let removals = Set.difference previousRanges desired
        let planned = Set.union previousRanges additions
        let resultingOwned = Set.union (Set.intersect previousRanges desired) additions
        persistIntent planned
        for range in additions do
            let start = range.Start.ToString(CultureInfo.InvariantCulture)
            let finish = (uint64 range.Start + uint64 range.Count - 1UL).ToString(CultureInfo.InvariantCulture)
            runRequired environment "usermod" [ addOption; start + "-" + finish; "--"; userName ] None |> ignore
        for range in removals do
            if Set.contains range current then
                let start = range.Start.ToString(CultureInfo.InvariantCulture)
                let finish = (uint64 range.Start + uint64 range.Count - 1UL).ToString(CultureInfo.InvariantCulture)
                runRequired environment "usermod" [ delOption; start + "-" + finish; "--"; userName ] None |> ignore
        persistIntent resultingOwned
        resultingOwned

    let private removeOwnedSubids (environment: HostEnvironment) (userName: string) (ranges: Set<IdRange>) (logicalPath: string) (delOption: string) : unit =
        let current = readSubordinateRanges environment logicalPath |> Map.tryFind userName |> Option.defaultValue Set.empty
        for range in ranges do
            if Set.contains range current then
                let start = range.Start.ToString(CultureInfo.InvariantCulture)
                let finish = (uint64 range.Start + uint64 range.Count - 1UL).ToString(CultureInfo.InvariantCulture)
                runRequired environment "usermod" [ delOption; start + "-" + finish; "--"; userName ] None |> ignore

    let private readKeyLinesForHome (environment: HostEnvironment) (userName: string) (home: string) (uid: uint32) (gid: uint32) : string list =
        match createOrOpenSshDirectory environment userName home uid false with
        | None -> []
        | Some(handle, _) ->
            use handle = handle
            match safeFileContentsAt (handle.DangerousGetHandle().ToInt32()) "authorized_keys" uid with
            | None -> []
            | Some text -> text.Split([| '\n' |], StringSplitOptions.RemoveEmptyEntries) |> Array.map (fun line -> line.TrimEnd('\r')) |> Array.toList

    let private writeKeyLines (environment: HostEnvironment) (userName: string) (home: string) (uid: uint32) (gid: uint32) (lines: string list) : unit =
        match createOrOpenSshDirectory environment userName home uid true with
        | None -> fail "account home directory does not exist"
        | Some(handle, _) ->
            use handle = handle
            let contents = if lines.IsEmpty then "" else String.concat "\n" lines + "\n"
            atomicWriteAt (handle.DangerousGetHandle().ToInt32()) "authorized_keys" uid gid contents


    let private revokeOwnedKeys (environment: HostEnvironment) (journal: Journal) (userName: string) (uid: int) (gid: int) (fallbackHome: string) (userRecord: UserOwnership) : Journal =
        let mutable currentJournal = journal
        let mutable record = userRecord
        let pendingHome = record.KeyPendingHome |> Option.orElse record.KeyHome |> Option.defaultValue fallbackHome
        let mutable lines =
            if pendingHome = "/nonexistent" then []
            else readKeyLinesForHome environment userName pendingHome (uint32 uid) (uint32 gid)
        if hasPendingKeys record then
            let before = record.KeyPendingBefore |> Option.defaultWith (fun () -> fail "Users key journal has no pending preimage")
            let after = record.KeyPendingAfter |> Option.defaultWith (fun () -> fail "Users key journal has no pending result")
            if record.KeyPendingHome <> Some pendingHome then fail "Users key journal has an inconsistent pending home"
            if lines = after then
                record <- commitPendingKeys record
                currentJournal <- persistUpdatedUser environment currentJournal userName record
            elif lines = before then
                record <- clearPendingKeys record
                currentJournal <- persistUpdatedUser environment currentJournal userName record
            else fail "authorized_keys changed while an owned key update was pending"
        match record.KeyMode, record.KeyHome with
        | Some mode, Some home ->
            lines <- readKeyLinesForHome environment userName home (uint32 uid) (uint32 gid)
            let updated =
                if mode = "exclusive" then
                    if lines <> record.KeyLines then fail "exclusive authorized_keys file was changed by a foreign writer"
                    []
                else lines |> List.filter (fun line -> not (Set.contains line record.KeysAdded))
            if updated <> lines then
                let intent = makeKeyIntent record mode home [] Set.empty lines updated
                currentJournal <- persistUpdatedUser environment currentJournal userName intent
                let observed = readKeyLinesForHome environment userName home (uint32 uid) (uint32 gid)
                if observed <> lines then fail "authorized_keys changed before an owned key revocation"
                writeKeyLines environment userName home (uint32 uid) (uint32 gid) updated
                record <- commitPendingKeys intent
                currentJournal <- persistUpdatedUser environment currentJournal userName record
            record <- { record with KeyMode = None; KeyHome = None; KeyLines = []; KeysAdded = Set.empty } |> clearPendingKeys
            currentJournal <- persistUpdatedUser environment currentJournal userName record
        | None, None ->
            if not record.KeysAdded.IsEmpty then fail "Users key journal has managed keys without a home"
        | _ -> fail "Users key journal has an incomplete authorized-key owner"
        currentJournal

    let private cleanupUserAccess (environment: HostEnvironment) (connectionUid: int option) (connectionName: string) (journal: Journal) (userName: string) (userRecord: UserOwnership) : Journal =
        let state = parseLocalState environment
        let account = Map.tryFind userName state.Users
        match account with
        | None ->
            if (lookupNss environment "passwd" userName).IsSome then fail "an NSS account now conflicts with a retained local identity"
            if state.Users |> Map.exists (fun _ user -> user.Uid = userRecord.Uid) then fail "owned UID was reused by another local identity"
            if (lookupNss environment "passwd" (userRecord.Uid.ToString(CultureInfo.InvariantCulture))).IsSome then fail "owned UID was reused by an NSS identity"
            if not userRecord.SubordinateUidsAdded.IsEmpty || not userRecord.SubordinateGidsAdded.IsEmpty then
                fail "cannot safely remove subordinate IDs after the local account disappeared"
            let groups = groupMemberships state userName
            for groupName in userRecord.MembershipsAdded do
                if Set.contains groupName groups then runRequired environment "gpasswd" [ "--delete"; userName; groupName ] None |> ignore
            revokeOwnedKeys environment journal userName userRecord.Uid userRecord.Gid (userRecord.KeyHome |> Option.defaultValue "/nonexistent") userRecord
        | Some user ->
            if user.Uid <> userRecord.Uid || user.Gid <> userRecord.Gid then fail "owned user name was reused by a different numeric identity"
            let revokesConnectionAccess =
                not userRecord.MembershipsAdded.IsEmpty
                || not userRecord.KeysAdded.IsEmpty
                || userRecord.KeyMode = Some "exclusive"
                || hasPendingKeys userRecord
                || not userRecord.SubordinateUidsAdded.IsEmpty
                || not userRecord.SubordinateGidsAdded.IsEmpty
            if userIsConnectionUser connectionUid (Some connectionName) user && revokesConnectionAccess then
                fail "refusing to revoke access from the active connection user"
            let groups = groupMemberships state userName
            for groupName in userRecord.MembershipsAdded do
                if Set.contains groupName groups then runRequired environment "gpasswd" [ "--delete"; userName; groupName ] None |> ignore
            removeOwnedSubids environment userName userRecord.SubordinateUidsAdded "/etc/subuid" "--del-subuids"
            removeOwnedSubids environment userName userRecord.SubordinateGidsAdded "/etc/subgid" "--del-subgids"
            revokeOwnedKeys environment journal userName user.Uid user.Gid user.Home userRecord

    let private applyUser (environment: HostEnvironment) (bounds: IdBounds) (connectionUid: int option) (connectionName: string) (state: LocalState) (journal: Journal) (spec: UserSpec) : LocalState * Journal =
        let prior = Map.tryFind spec.Name journal.Users
        let accountBefore = Map.tryFind spec.Name state.Users
        let identity, stateAfterCreate, journalAfterCreate =
            match accountBefore with
            | Some account ->
                if account.Uid = 0 then fail "the root account cannot be managed by Users"
                let identityRecord =
                    match prior with
                    | Some owned ->
                        if owned.Uid <> account.Uid || owned.Gid <> account.Gid then fail "owned user numeric identity changed"
                        if owned.Identity = "created" || owned.Identity = "adopted" then owned.Identity else fail "Users ownership identity is malformed"
                    | None when spec.Existing = "adopt" -> "adopted"
                    | None -> fail "existing unowned user was rejected; request existing=adopt"
                ensureNssUserMatches environment state spec.Name |> ignore
                match spec.Uid with Some value when value <> account.Uid -> fail "changing an existing user UID is not supported" | _ -> ()
                match spec.Kind with
                | Some kind ->
                    let lower, upper = getIdBounds bounds kind true
                    if account.Uid < lower || account.Uid > upper then fail "existing user UID does not match its declared kind"
                | None -> ()
                let record = makeUserRecord account.Uid account.Gid identityRecord
                let record =
                    prior
                    |> Option.map (fun existing ->
                        { record with
                            CreationComplete = existing.CreationComplete
                            CreationHomeKind = existing.CreationHomeKind
                            CreationHomePath = existing.CreationHomePath
                            CreationHomeMode = existing.CreationHomeMode
                            CreationHomeSkeleton = existing.CreationHomeSkeleton
                            CreationShell = existing.CreationShell
                            MembershipsAdded = existing.MembershipsAdded
                            KeyMode = existing.KeyMode
                            KeyHome = existing.KeyHome
                            KeyLines = existing.KeyLines
                            KeyPendingBefore = existing.KeyPendingBefore
                            KeyPendingAfter = existing.KeyPendingAfter
                            KeyPendingDesired = existing.KeyPendingDesired
                            KeyPendingMode = existing.KeyPendingMode
                            KeyPendingHome = existing.KeyPendingHome
                            KeyPendingAdded = existing.KeyPendingAdded
                            KeysAdded = existing.KeysAdded
                            SubordinateUidsAdded = existing.SubordinateUidsAdded
                            SubordinateGidsAdded = existing.SubordinateGidsAdded
                            PasswordKind = existing.PasswordKind
                            PasswordDigest = existing.PasswordDigest })
                    |> Option.defaultValue record
                let saved = persistUpdatedUser environment journal spec.Name record
                identityRecord, state, saved
            | None ->
                match prior with
                | Some owned when owned.Identity = "created" && not owned.CreationComplete -> ()
                | Some _ -> fail "an owned user disappeared after creation completed"
                | None when spec.Existing = "adopt" -> fail "cannot adopt a user that does not exist"
                | _ -> ()
                if spec.Name = connectionName then fail "the active connection user cannot be created or managed"
                let createdState, createdJournal = createNewUser environment bounds state journal spec connectionUid connectionName
                "created", createdState, createdJournal
        let account = ensureUserEntry stateAfterCreate spec.Name
        if userIsConnectionUser connectionUid (Some connectionName) account then
            let pendingCreationRepair =
                prior
                |> Option.exists (fun owned -> owned.Identity = "created" && not owned.CreationComplete)
            let requestedMutation =
                pendingCreationRepair
                || spec.Description.IsSome
                || spec.Shell.IsSome
                || spec.Home.IsSome
                || spec.Password.IsSome
                || spec.Expiry.IsSome
                || not spec.PasswordPolicy.IsEmpty
                || spec.SubordinateUids.IsSome
                || spec.SubordinateGids.IsSome
                || spec.AuthorizedKeys.IsSome
            if requestedMutation then fail "refusing account or credential changes for the active connection user"
        match spec.PrimaryGroup with
        | Some("private", _) when accountBefore.IsSome && primaryGroupName stateAfterCreate account.Gid <> Some spec.Name -> fail "changing an existing primary group is not supported"
        | Some("existing", Some name) when accountBefore.IsSome && primaryGroupName stateAfterCreate account.Gid <> Some name -> fail "changing an existing primary group is not supported"
        | Some("existing", Some name) -> ensureGroupEntry stateAfterCreate name |> ignore
        | _ -> ()
        match spec.Home with
        | Some home when accountBefore.IsSome -> ensureHomeForExisting environment home account
        | _ -> ()
        let mutable currentState = parseLocalState environment
        let currentAccount = ensureUserEntry currentState spec.Name
        let previousRecord = getUserState journalAfterCreate spec.Name
        let mutable record = { previousRecord with Uid = currentAccount.Uid; Gid = currentAccount.Gid; Identity = identity }
        let creationIncomplete = identity = "created" && not record.CreationComplete
        let newlyCreated = creationIncomplete
        if creationIncomplete && spec.Home.IsNone then
            match record.CreationHomeKind, record.CreationHomePath with
            | Some "none", None ->
                if currentAccount.Home <> "/nonexistent" then fail "incomplete account creation has an unexpected home path"
            | Some kind, Some path when currentAccount.Home = path ->
                let home =
                    { Kind = kind
                      Path = Some path
                      Mode = record.CreationHomeMode
                      Skeleton = record.CreationHomeSkeleton }
                ensureHomeForExisting environment home currentAccount
            | _ -> fail "incomplete account creation has an unexpected home identity"
        let scalarArgs = ResizeArray<string>()
        match spec.Description with Some value when value <> currentAccount.Description -> scalarArgs.Add("--comment"); scalarArgs.Add(value) | _ -> ()
        let desiredShell =
            match spec.Shell with
            | Some value -> Some value
            | None when creationIncomplete -> record.CreationShell
            | None -> None
        match desiredShell with Some value when value <> currentAccount.Shell -> scalarArgs.Add("--shell"); scalarArgs.Add(value) | _ -> ()
        if scalarArgs.Count > 0 then runUsermod environment spec.Name (List.ofSeq scalarArgs)
        currentState <- parseLocalState environment
        let currentAccount = ensureUserEntry currentState spec.Name
        let passwordToApply =
            match spec.Password with
            | Some _ -> spec.Password
            | None when creationIncomplete -> Some { Kind = "locked"; Hash = None; Update = "always" }
            | None -> None
        record <- applyPassword environment spec.Name currentState record passwordToApply newlyCreated
        applyExpiryAndPolicy environment spec.Name spec.Expiry spec.PasswordPolicy
        currentState <- parseLocalState environment
        let membershipsBefore = groupMemberships currentState spec.Name
        match spec.SupplementaryGroups with
        | None ->
            if userIsConnectionUser connectionUid (Some connectionName) currentAccount && not record.MembershipsAdded.IsEmpty then fail "refusing to revoke group access from the active connection user"
            for groupName in record.MembershipsAdded do
                if Set.contains groupName membershipsBefore then runRequired environment "gpasswd" [ "--delete"; spec.Name; groupName ] None |> ignore
            record <- { record with MembershipsAdded = Set.empty }
        | Some(mode, names) ->
            for groupName in names do
                ensureGroupEntry currentState groupName |> ignore
                ensureNssGroupMatches environment currentState groupName |> ignore
            let target = Set.ofList names
            let additions = Set.difference target membershipsBefore
            let removeOwned = Set.difference record.MembershipsAdded target
            let changed =
                if mode = "exclusive" then membershipsBefore <> target
                else not additions.IsEmpty || not removeOwned.IsEmpty
            if userIsConnectionUser connectionUid (Some connectionName) currentAccount && changed then fail "refusing to change group memberships for the active connection user"
            let plannedRecord = { record with MembershipsAdded = Set.union record.MembershipsAdded additions }
            persistUpdatedUser environment journalAfterCreate spec.Name plannedRecord |> ignore
            if mode = "exclusive" then
                if membershipsBefore <> target then runUsermod environment spec.Name [ "--groups"; String.Join(",", names) ]
            else
                for groupName in removeOwned do
                    if Set.contains groupName membershipsBefore then runRequired environment "gpasswd" [ "--delete"; spec.Name; groupName ] None |> ignore
                if not additions.IsEmpty then runUsermod environment spec.Name [ "--append"; "--groups"; String.Join(",", additions) ]
            record <- { plannedRecord with MembershipsAdded = Set.difference plannedRecord.MembershipsAdded removeOwned }
            persistUpdatedUser environment journalAfterCreate spec.Name record |> ignore
        currentState <- parseLocalState environment
        let existingHome = currentAccount.Home
        if spec.AuthorizedKeys.IsSome && existingHome = "/nonexistent" then fail "authorized keys require an account home directory"
        let mutable currentKeyLines =
            if existingHome = "/nonexistent" then []
            else readKeyLinesForHome environment spec.Name existingHome (uint32 currentAccount.Uid) (uint32 currentAccount.Gid)
        let mutable retryingPendingKeyIntent = false
        if hasPendingKeys record then
            let before = record.KeyPendingBefore |> Option.defaultWith (fun () -> fail "Users key journal has no pending preimage")
            let after = record.KeyPendingAfter |> Option.defaultWith (fun () -> fail "Users key journal has no pending result")
            if record.KeyPendingHome <> Some existingHome then fail "account home changed during a pending authorized-key update"
            if currentKeyLines = after then
                record <- commitPendingKeys record
                persistUpdatedUser environment journalAfterCreate spec.Name record |> ignore
            elif currentKeyLines = before then
                match spec.AuthorizedKeys with
                | None ->
                    record <- clearPendingKeys record
                    persistUpdatedUser environment journalAfterCreate spec.Name record |> ignore
                | Some keys ->
                    let desired = keys.Keys |> List.map renderKey
                    if record.KeyPendingMode <> Some keys.Mode || record.KeyPendingDesired <> Some desired then
                        fail "a pending authorized-key update must be retried with its original desired keys"
                    retryingPendingKeyIntent <- true
            else fail "authorized_keys changed while an owned key update was pending"
        match spec.AuthorizedKeys with
        | None ->
            if record.KeyMode.IsSome || not record.KeysAdded.IsEmpty then
                let home = record.KeyHome |> Option.defaultValue existingHome
                if userIsConnectionUser connectionUid (Some connectionName) currentAccount then fail "refusing to revoke authorized keys for the active connection user"
                if record.KeyMode = Some "exclusive" && currentKeyLines <> record.KeyLines then
                    fail "exclusive authorized_keys file was changed by a foreign writer"
                let updatedLines =
                    if record.KeyMode = Some "exclusive" then []
                    else currentKeyLines |> List.filter (fun line -> not (Set.contains line record.KeysAdded))
                if updatedLines <> currentKeyLines then
                    let mode = record.KeyMode |> Option.defaultValue "managed"
                    let intent = makeKeyIntent record mode home [] Set.empty currentKeyLines updatedLines
                    persistUpdatedUser environment journalAfterCreate spec.Name intent |> ignore
                    let observed = readKeyLinesForHome environment spec.Name home (uint32 currentAccount.Uid) (uint32 currentAccount.Gid)
                    if observed <> currentKeyLines then fail "authorized_keys changed before an owned key revocation"
                    writeKeyLines environment spec.Name home (uint32 currentAccount.Uid) (uint32 currentAccount.Gid) updatedLines
                    record <- commitPendingKeys intent
                    persistUpdatedUser environment journalAfterCreate spec.Name record |> ignore
                record <- { record with KeyMode = None; KeyHome = None; KeyLines = []; KeysAdded = Set.empty } |> clearPendingKeys
                persistUpdatedUser environment journalAfterCreate spec.Name record |> ignore
            elif hasPendingKeys record then fail "Users key journal contains an unhandled pending intent"
        | Some keySet ->
            let desired = keySet.Keys |> List.map renderKey
            if retryingPendingKeyIntent then
                let after = record.KeyPendingAfter |> Option.defaultWith (fun () -> fail "Users key journal has no pending result")
                if currentKeyLines <> after then
                    let before = record.KeyPendingBefore |> Option.defaultWith (fun () -> fail "Users key journal has no pending preimage")
                    let observed = readKeyLinesForHome environment spec.Name existingHome (uint32 currentAccount.Uid) (uint32 currentAccount.Gid)
                    if observed <> before then fail "authorized_keys changed before a pending owned key update"
                    writeKeyLines environment spec.Name existingHome (uint32 currentAccount.Uid) (uint32 currentAccount.Gid) after
                    currentKeyLines <- after
                record <- commitPendingKeys record
                persistUpdatedUser environment journalAfterCreate spec.Name record |> ignore
            else
                let oldOwned =
                    if record.KeyHome <> Some existingHome then Set.empty
                    else
                        match record.KeyMode with
                        | Some "managed" -> record.KeysAdded
                        | Some "exclusive" -> Set.ofList record.KeyLines
                        | _ -> Set.empty
                let retained = currentKeyLines |> List.filter (fun line -> not (Set.contains line oldOwned))
                let newOwned = desired |> List.filter (fun line -> not (List.contains line retained)) |> Set.ofList
                let after =
                    if keySet.Mode = "exclusive" then desired
                    else retained @ (desired |> List.filter (fun line -> not (List.contains line retained)))
                let plannedOwned = if keySet.Mode = "managed" then Set.union oldOwned newOwned else Set.empty
                let intent = makeKeyIntent record keySet.Mode existingHome desired plannedOwned currentKeyLines after
                persistUpdatedUser environment journalAfterCreate spec.Name intent |> ignore
                let observed = readKeyLinesForHome environment spec.Name existingHome (uint32 currentAccount.Uid) (uint32 currentAccount.Gid)
                if observed <> currentKeyLines then fail "authorized_keys changed before an owned key update"
                if after <> currentKeyLines then writeKeyLines environment spec.Name existingHome (uint32 currentAccount.Uid) (uint32 currentAccount.Gid) after
                record <- commitPendingKeys intent
                persistUpdatedUser environment journalAfterCreate spec.Name record |> ignore
        let requestedUids = spec.SubordinateUids
        let requestedGids = spec.SubordinateGids
        let persistUidIntent ranges =
            record <- { record with SubordinateUidsAdded = ranges }
            persistUpdatedUser environment journalAfterCreate spec.Name record |> ignore
        let persistGidIntent ranges =
            record <- { record with SubordinateGidsAdded = ranges }
            persistUpdatedUser environment journalAfterCreate spec.Name record |> ignore
        let uidRanges =
            if requestedUids.IsNone then
                removeOwnedSubids environment spec.Name record.SubordinateUidsAdded "/etc/subuid" "--del-subuids"
                Set.empty
            else
                applySubordinateSet environment spec.Name record.SubordinateUidsAdded requestedUids "/etc/subuid" "--add-subuids" "--del-subuids" persistUidIntent
        record <- { record with SubordinateUidsAdded = uidRanges }
        let gidRanges =
            if requestedGids.IsNone then
                removeOwnedSubids environment spec.Name record.SubordinateGidsAdded "/etc/subgid" "--del-subgids"
                Set.empty
            else
                applySubordinateSet environment spec.Name record.SubordinateGidsAdded requestedGids "/etc/subgid" "--add-subgids" "--del-subgids" persistGidIntent
        record <- { record with SubordinateUidsAdded = uidRanges; SubordinateGidsAdded = gidRanges }
        record <- { record with CreationComplete = true }
        let updatedJournal = persistUpdatedUser environment journalAfterCreate spec.Name record
        parseLocalState environment, updatedJournal


    let private processAbsentUser (environment: HostEnvironment) (bounds: IdBounds) (connectionUid: int option) (connectionName: string) (connectionGroups: Set<int>) (state: LocalState) (journal: Journal) (spec: UserSpec) (groupSpecs: GroupSpec list) : Journal =
        let owned = Map.tryFind spec.Name journal.Users
        match Map.tryFind spec.Name state.Users with
        | None ->
            match owned with
            | None -> journal
            | Some record ->
                let cleanedJournal = cleanupUserAccess environment connectionUid connectionName journal spec.Name record
                withoutUserUserRecord cleanedJournal spec.Name
        | Some user ->
            if user.Uid = 0 then fail "the root account cannot be removed by Users"
            if userIsConnectionUser connectionUid (Some connectionName) user then fail "the active connection user cannot be removed"
            let identityRecord = owned |> Option.defaultWith (fun () -> if spec.Existing = "adopt" then makeUserRecord user.Uid user.Gid "adopted" else fail "removing an existing unowned user requires existing=adopt")
            if identityRecord.Uid <> user.Uid || identityRecord.Gid <> user.Gid then fail "owned user name was reused by a different numeric identity"
            ensureNssUserMatches environment state spec.Name |> ignore
            let primaryGroup = primaryGroupName state user.Gid
            let candidateGroups =
                [ match primaryGroup with
                  | Some name when groupSpecs |> List.exists (fun value -> value.Name = name && value.State = "absent") -> yield name
                  | _ -> ()
                  if bounds.UserGroupsEnabled && Map.containsKey spec.Name state.Groups then yield spec.Name ]
                |> List.distinct
            let groupsToRemove =
                candidateGroups
                |> List.map (fun groupName ->
                    let groupSpec =
                        groupSpecs
                        |> List.tryFind (fun value -> value.Name = groupName && value.State = "absent")
                        |> Option.defaultWith (fun () -> fail "userdel may remove its same-named group; declare it absent explicitly")
                    let group = ensureGroupEntry state groupName
                    if Set.contains group.Gid bounds.ReservedGroupIds then fail "private group GID is reserved by another Users resource"
                    let groupOwner =
                        match Map.tryFind groupName journal.Groups with
                        | Some current when current.Gid = group.Gid -> current
                        | Some _ -> fail "owned private group name was reused by a different numeric identity"
                        | None when groupSpec.Existing = "adopt" -> makeGroupRecord group.Gid "adopted" None
                        | None -> fail "user deletion would also remove an unowned primary group"
                    ensureNssGroupMatches environment state groupName |> ignore
                    if Set.contains group.Gid connectionGroups then fail "refusing to remove a primary group used by the active connection user"
                    if state.Users |> Map.exists (fun otherName other -> otherName <> spec.Name && other.Gid = group.Gid) then
                        fail "cannot remove a primary group used by another account"
                    if group.Members |> Set.exists ((<>) spec.Name) then
                        fail "cannot remove a primary group with foreign supplementary members"
                    groupName, groupOwner)
            let primaryGroupToRemove = groupsToRemove |> List.tryFind (fun (groupName, _) -> groupName = spec.Name)
            let processResult = runCommand environment "pgrep" [ "-u"; user.Uid.ToString(CultureInfo.InvariantCulture) ] None
            if processResult.ExitCode = 0 then fail "refusing to remove a user with active processes"
            if processResult.ExitCode <> 1 then fail ("pgrep failed (exit status " + processResult.ExitCode.ToString(CultureInfo.InvariantCulture) + ")")
            let mutable intentJournal =
                match primaryGroupToRemove with
                | Some(name, groupRecord) when not (Map.containsKey name journal.Groups) ->
                    persistUpdatedGroup environment journal name groupRecord
                | _ -> journal
            if owned.IsNone then intentJournal <- persistUpdatedUser environment intentJournal spec.Name identityRecord
            let cleanedJournal = cleanupUserAccess environment connectionUid connectionName intentJournal spec.Name identityRecord
            runRequired environment "userdel" [ "--"; spec.Name ] None |> ignore
            let refreshed = parseLocalState environment
            if Map.containsKey spec.Name refreshed.Users then fail "userdel did not remove the local account"
            withoutUserUserRecord cleanedJournal spec.Name

    let private processAbsentGroup (environment: HostEnvironment) (connectionUid: int option) (connectionGroups: Set<int>) (state: LocalState) (journal: Journal) (spec: GroupSpec) : Journal =
        match Map.tryFind spec.Name state.Groups with
        | None -> withoutGroupRecord journal spec.Name
        | Some group ->
            let owned = Map.tryFind spec.Name journal.Groups
            let identity =
                match owned with
                | Some value when value.Gid = group.Gid -> value
                | Some _ -> fail "owned group name was reused by a different numeric identity"
                | None when spec.Existing = "adopt" -> makeGroupRecord group.Gid "adopted" None
                | None -> fail "removing an existing unowned group requires existing=adopt"
            ensureNssGroupMatches environment state spec.Name |> ignore
            if Set.contains group.Gid connectionGroups || (connectionUid |> Option.exists (fun uid -> state.Users |> Map.exists (fun _ user -> user.Uid = uid && user.Gid = group.Gid))) then
                fail "refusing to remove a group used by the active connection user"
            if state.Users |> Map.exists (fun _ user -> user.Gid = group.Gid) then fail "cannot remove a group used as a primary group"
            if not group.Members.IsEmpty then fail "cannot remove a group that still has supplementary members"
            let intentJournal =
                if owned.IsSome then journal
                else persistUpdatedGroup environment journal spec.Name identity
            runRequired environment "groupdel" [ "--"; spec.Name ] None |> ignore
            if Map.containsKey spec.Name (parseLocalState environment).Groups then fail "groupdel did not remove the local group"
            withoutGroupRecord intentJournal spec.Name

    let private cleanupRemovedUsers (environment: HostEnvironment) (connectionUid: int option) (connectionName: string) (desiredNames: Set<string>) (state: LocalState) (journal: Journal) : Journal =
        let omitted = journal.Users |> Map.toSeq |> Seq.map fst |> Seq.filter (fun name -> not (Set.contains name desiredNames)) |> Seq.toList
        let mutable current = journal
        for name in omitted do
            let record = current.Users[name]
            current <- cleanupUserAccess environment connectionUid connectionName current name record
            current <- withoutUserUserRecord current name
            persistJournal environment current
        current
    let private ensureConnectionResourcesExternal (request: Request) (state: LocalState) (connectionUid: int option) (connectionGroups: Set<int>) (journal: Journal option) : unit =
        let isConnectionName (name: string) =
            name = request.ConnectionUser
            || (connectionUid
                |> Option.exists (fun uid ->
                    Map.tryFind name state.Users
                    |> Option.exists (fun user -> user.Uid = uid)))
        let declaredConnectionUser =
            request.Users
            |> List.exists (fun spec ->
                isConnectionName spec.Name
                || (connectionUid |> Option.exists (fun uid -> spec.Uid = Some uid)))
        if declaredConnectionUser then fail "the active connection user must remain externally managed"
        let ownedConnectionUser =
            journal
            |> Option.exists (fun owned ->
                owned.Users
                |> Map.exists (fun name record -> isConnectionName name || connectionUid = Some record.Uid))
        if ownedConnectionUser then fail "the active connection user is already owned by Users and must remain externally managed"
        let removesConnectionGroup =
            request.Groups
            |> List.exists (fun spec ->
                spec.State = "absent"
                && (Map.tryFind spec.Name state.Groups
                    |> Option.exists (fun group -> Set.contains group.Gid connectionGroups)))
        if removesConnectionGroup then fail "refusing to remove a group used by the active connection user"


    let private createActual (environment: HostEnvironment) (bounds: IdBounds) (state: LocalState) (groups: Map<string, GroupOwnership>) (users: Map<string, UserOwnership>) (requestedGroups: GroupSpec list) (requestedUsers: UserSpec list) : JsonObject =
        let groupNames =
            (requestedGroups |> List.map (fun group -> group.Name)) @ (groups |> Map.toList |> List.map fst)
            |> List.distinct
            |> List.sort
        let userNames =
            (requestedUsers |> List.map (fun user -> user.Name)) @ (users |> Map.toList |> List.map fst)
            |> List.distinct
            |> List.sort
        let actual = JsonObject()
        let groupArray = JsonArray()
        for name in groupNames do
            let desiredKind = requestedGroups |> List.tryFind (fun group -> group.Name = name) |> Option.bind (fun group -> group.Kind) |> Option.orElseWith (fun () -> Map.tryFind name groups |> Option.bind (fun group -> group.Kind))
            groupArray.Add(actualGroupNode bounds state name desiredKind)
        actual["groups"] <- groupArray
        let userArray = JsonArray()
        let uidRanges = readSubordinateRanges environment "/etc/subuid"
        let gidRanges = readSubordinateRanges environment "/etc/subgid"
        for name in userNames do userArray.Add(actualUserNode environment state uidRanges gidRanges name)
        actual["users"] <- userArray
        actual

    let private desiredInSync (environment: HostEnvironment) (bounds: IdBounds) (state: LocalState) (journal: Journal) (requestedGroups: GroupSpec list) (requestedUsers: UserSpec list) : bool =
        let groupsSync =
            requestedGroups
            |> List.forall (fun spec ->
                match spec.State, Map.tryFind spec.Name state.Groups with
                | "absent", None -> not (Map.containsKey spec.Name journal.Groups)
                | "absent", Some _ -> false
                | "present", Some group ->
                    (spec.Gid |> Option.forall ((=) group.Gid))
                    && (spec.Kind |> Option.forall (fun kind -> kindForId bounds false group.Gid = kind))
                    && (Map.tryFind spec.Name journal.Groups |> Option.exists (fun value -> value.Gid = group.Gid))
                | _ -> false)
        let usersSync =
            requestedUsers
            |> List.forall (fun spec ->
                match spec.State, Map.tryFind spec.Name state.Users with
                | "absent", None -> not (Map.containsKey spec.Name journal.Users)
                | "absent", Some _ -> false
                | "present", Some user ->
                    let shadow = Map.tryFind spec.Name state.Shadows
                    let owner = Map.tryFind spec.Name journal.Users
                    let groupName = primaryGroupName state user.Gid
                    let supplementary = groupMemberships state spec.Name
                    let observedKeys = accountKeys environment user
                    let checkPassword =
                        match spec.Password, shadow, owner with
                        | None, _, _ -> true
                        | Some password, Some current, Some owned when password.Kind = "locked" ->
                            owned.PasswordKind = Some "locked"
                            && (current.PasswordHash.StartsWith("!", StringComparison.Ordinal) || current.PasswordHash.StartsWith("*", StringComparison.Ordinal))
                        | Some password, Some current, Some owned when password.Kind = "hash" && password.Update = "onCreate" && owned.PasswordKind = Some "onCreate" -> true
                        | Some password, Some current, Some owned when password.Kind = "hash" ->
                            let expected = password.Hash |> Option.map hashDigest
                            owned.PasswordKind = Some "hash"
                            && owned.PasswordDigest = expected
                            && owned.PasswordDigest = Some(hashDigest current.PasswordHash)
                        | _ -> false
                    let checkExpiry =
                        match spec.Expiry, shadow with
                        | None, _ -> true
                        | Some("never", _), Some current -> current.ExpiryDay.IsNone
                        | Some("on", Some date), Some current ->
                            let actualDate =
                                current.ExpiryDay
                                |> Option.map (fun days -> DateOnly.FromDateTime(DateTime.UnixEpoch.AddDays(float days)).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture))
                            actualDate = Some date
                        | _ -> false
                    let checkPolicy =
                        match shadow with
                        | None when not spec.PasswordPolicy.IsEmpty -> false
                        | None -> true
                        | Some current ->
                            spec.PasswordPolicy
                            |> Map.forall (fun name expected ->
                                let observed =
                                    match name with
                                    | "minDays" -> current.MinimumDays
                                    | "maxDays" -> current.MaximumDays
                                    | "warnDays" -> current.WarningDays
                                    | _ -> current.InactiveDays
                                observed = Some expected)
                    let checkSupplementary =
                        match spec.SupplementaryGroups with
                        | None -> owner |> Option.exists (fun value -> value.MembershipsAdded.IsEmpty)
                        | Some("managed", names) -> names |> List.forall (fun name -> Set.contains name supplementary)
                        | Some("exclusive", names) -> supplementary = Set.ofList names
                        | _ -> false
                    let checkKeys =
                        match spec.AuthorizedKeys, owner with
                        | None, Some owned -> owned.KeyMode.IsNone && owned.KeysAdded.IsEmpty && not (hasPendingKeys owned)
                        | None, None -> false
                        | Some keySet, Some owned ->
                            let desired = keySet.Keys |> List.map renderKey
                            owned.KeyMode = Some keySet.Mode
                            && owned.KeyHome = Some user.Home
                            && not (hasPendingKeys owned)
                            && (if keySet.Mode = "exclusive" then observedKeys = desired && owned.KeyLines = desired
                                else
                                    (desired |> List.forall (fun line -> List.contains line observedKeys))
                                    && (owned.KeysAdded |> Set.forall (fun line -> List.contains line observedKeys)))
                        | _ -> false
                    let checkHome =
                        spec.Home
                        |> Option.forall (fun home ->
                            match home.Kind, home.Path with
                            | "none", None -> user.Home = "/nonexistent"
                            | ("create" | "existing"), Some path when user.Home = path ->
                                match openDirectoryChain environment path false 0o700 (Some(uint32 user.Uid)) with
                                | None -> false
                                | Some(handle, metadata) ->
                                    use handle = handle
                                    metadata.FileType = directoryType
                                    && (home.Mode |> Option.forall ((=) metadata.Mode))
                            | _ -> false)
                    let checkSubordinate (path: string) (requested: IdRange list option) (ownedRanges: Set<IdRange>) : bool =
                        match requested with
                        | None -> ownedRanges.IsEmpty
                        | Some ranges ->
                            let current = readSubordinateRanges environment path |> Map.tryFind spec.Name |> Option.defaultValue Set.empty
                            (ranges |> List.forall (fun range -> Set.contains range current))
                            && (ownedRanges |> Set.forall (fun range -> Set.contains range current))
                    let identityMatches =
                        match owner with
                        | Some owned -> owned.Uid = user.Uid && owned.Gid = user.Gid && owned.CreationComplete && user.Uid <> 0
                        | None -> false
                    identityMatches
                    && (spec.Uid |> Option.forall ((=) user.Uid))
                    && (spec.Kind |> Option.forall (fun kind -> kindForId bounds true user.Uid = kind))
                    && (spec.Description |> Option.forall ((=) user.Description))
                    && (spec.Shell |> Option.forall ((=) user.Shell))
                    && (spec.PrimaryGroup |> Option.forall (fun (kind, name) -> if kind = "private" then groupName = Some spec.Name else name = groupName))
                    && checkHome
                    && checkPassword
                    && checkExpiry
                    && checkPolicy
                    && checkSupplementary
                    && checkSubordinate "/etc/subuid" spec.SubordinateUids (owner |> Option.map (fun value -> value.SubordinateUidsAdded) |> Option.defaultValue Set.empty)
                    && checkSubordinate "/etc/subgid" spec.SubordinateGids (owner |> Option.map (fun value -> value.SubordinateGidsAdded) |> Option.defaultValue Set.empty)
                    && checkKeys
                | _ -> false)
        groupsSync && usersSync

    let private readOperation (environment: HostEnvironment) (request: Request) : JsonNode =
        requireRootIfProduction environment
        let mutable bounds = readBounds environment
        let state = parseLocalState environment
        let journal = readJournal environment request.ResourceId
        match journal with
        | None ->
            let emptyJournal: Journal = { OwnerId = request.ResourceId; Groups = Map.empty; Users = Map.empty }
            let actual = createActual environment bounds state emptyJournal.Groups emptyJournal.Users request.Groups request.Users
            envelope false false actual
        | Some owned ->
            verifyJournalIdentities environment state owned
            let actual = createActual environment bounds state owned.Groups owned.Users request.Groups request.Users
            let inSync = desiredInSync environment bounds state owned request.Groups request.Users
            envelope true inSync actual

    let private applyOperation (environment: HostEnvironment) (request: Request) : JsonNode =
        requireRootIfProduction environment
        match ensureStateDirectory environment true with
        | None -> fail "cannot create Users ownership directory"
        | Some _ -> ()
        let stateDirectory = actualPath environment ownerDirectory
        let lockPath = Path.Combine(stateDirectory, ".lock")
        let lockMetadata =
            match inspectPath lockPath with
            | Some metadata ->
                if metadata.FileType <> regularType then fail "Users lock path is not a regular file"
                validateSecureRegularFile environment metadata "Users host lock"
                metadata
            | None -> { FileType = regularType; Mode = 0o600; UserId = effectiveOwner environment; GroupId = nativeGetEffectiveGroupId(); LinkCount = 1u; Inode = 0UL; DeviceMajor = 0u; DeviceMinor = 0u; Size = 0UL }
        ignore lockMetadata
        use hostLock = HostFiles.lockFile lockPath
        match inspectPath lockPath with
        | Some metadata -> validateSecureRegularFile environment metadata "Users host lock"
        | None -> fail "Users host lock disappeared after acquisition"
        let mutable bounds = readBounds environment
        let mutable state = parseLocalState environment
        let connectionUid, _, connectionGroups = connectionIdentity environment state request.ConnectionUser |> Option.map (fun (uid, gid, groups) -> Some uid, gid, groups) |> Option.defaultValue (None, 0, Set.empty)
        let prior = readJournal environment request.ResourceId |> Option.defaultValue { OwnerId = request.ResourceId; Groups = Map.empty; Users = Map.empty }
        ensureConnectionResourcesExternal request state connectionUid connectionGroups (Some prior)
        let reservedUserIds, reservedGroupIds = validateOwnerConflicts environment request.ResourceId prior (request.Groups |> List.map (fun value -> value.Name)) (request.Users |> List.map (fun value -> value.Name))
        bounds <- { bounds with ReservedUserIds = reservedUserIds; ReservedGroupIds = reservedGroupIds }
        for group in request.Groups do
            match Map.tryFind group.Name state.Groups with
            | Some _ -> ensureNssGroupMatches environment state group.Name |> ignore
            | None -> match lookupNss environment "group" group.Name with Some _ when group.State = "present" -> fail "an NSS group already uses this name" | _ -> ()
        for user in request.Users do
            match Map.tryFind user.Name state.Users with
            | Some _ -> ensureNssUserMatches environment state user.Name |> ignore
            | None -> match lookupNss environment "passwd" user.Name with Some _ when user.State = "present" -> fail "an NSS account already uses this name" | _ -> ()
        let mutable journal = prior
        for group in request.Groups do
            if group.State = "present" then
                let refreshed, updated = createOrAdoptDeclaredGroup environment bounds state journal group
                state <- refreshed
                journal <- updated
        let absentUsers = request.Users |> List.filter (fun value -> value.State = "absent")
        for spec in request.Users |> List.filter (fun value -> value.State = "present") do
            let nextState, nextJournal = applyUser environment bounds connectionUid request.ConnectionUser state journal spec
            state <- nextState
            journal <- nextJournal
        for spec in absentUsers do
            state <- parseLocalState environment
            journal <- processAbsentUser environment bounds connectionUid request.ConnectionUser connectionGroups state journal spec request.Groups
            persistJournal environment journal
        for spec in request.Groups |> List.filter (fun value -> value.State = "absent") do
            state <- parseLocalState environment
            journal <- processAbsentGroup environment connectionUid connectionGroups state journal spec
            persistJournal environment journal
        let desiredNames = request.Users |> List.map (fun value -> value.Name) |> Set.ofList
        journal <- cleanupRemovedUsers environment connectionUid request.ConnectionUser desiredNames (parseLocalState environment) journal
        // Omitted groups are retained, but their ownership record is relinquished.
        let retainedPrivateGroups =
            request.Users
            |> List.choose (fun spec ->
                if spec.State <> "present" then None
                else
                    match Map.tryFind spec.Name journal.Users, Map.tryFind spec.Name state.Users with
                    | Some owned, Some user when Map.containsKey spec.Name journal.Groups && primaryGroupName state user.Gid = Some spec.Name ->
                        match spec.PrimaryGroup with
                        | Some("private", _) -> Some spec.Name
                        | Some("existing", Some name) when name = spec.Name -> Some spec.Name
                        | None when owned.Identity = "created" -> Some spec.Name
                        | _ -> None
                    | _ -> None)
            |> Set.ofList
        let desiredGroupNames = Set.union (request.Groups |> List.map (fun value -> value.Name) |> Set.ofList) retainedPrivateGroups
        for name in journal.Groups.Keys |> Seq.toList do
            if not (Set.contains name desiredGroupNames) then journal <- withoutGroupRecord journal name
        persistJournal environment journal
        state <- parseLocalState environment
        let actual = createActual environment bounds state journal.Groups journal.Users request.Groups request.Users
        ensureConnectionTransport environment state request.ConnectionUser
        envelope true (desiredInSync environment bounds state journal request.Groups request.Users) actual

    let private deleteOperation (environment: HostEnvironment) (request: Request) : JsonNode =
        requireRootIfProduction environment
        let initialState = parseLocalState environment
        let initialConnectionUid, _, initialConnectionGroups =
            connectionIdentity environment initialState request.ConnectionUser
            |> Option.map (fun (uid, gid, groups) -> Some uid, gid, groups)
            |> Option.defaultValue (None, 0, Set.empty)
        ensureConnectionResourcesExternal request initialState initialConnectionUid initialConnectionGroups None
        match ensureStateDirectory environment false with
        | None ->
            let bounds = readBounds environment
            let actual = createActual environment bounds initialState Map.empty Map.empty request.Groups request.Users
            envelope false true actual
        | Some stateDirectory ->
            let lockPath = Path.Combine(stateDirectory, ".lock")
            match inspectPath lockPath with
            | Some metadata -> validateSecureRegularFile environment metadata "Users host lock"
            | None -> ()
            use hostLock = HostFiles.lockFile lockPath
            match inspectPath lockPath with
            | Some metadata -> validateSecureRegularFile environment metadata "Users host lock"
            | None -> fail "Users host lock disappeared after acquisition"
            match readJournal environment request.ResourceId with
            | None ->
                let bounds = readBounds environment
                let state = parseLocalState environment
                let empty: Journal = { OwnerId = request.ResourceId; Groups = Map.empty; Users = Map.empty }
                envelope false true (createActual environment bounds state empty.Groups empty.Users request.Groups request.Users)
            | Some journal ->
                let mutable state = parseLocalState environment
                verifyJournalIdentities environment state journal
                let connectionUid, _, connectionGroups =
                    connectionIdentity environment state request.ConnectionUser
                    |> Option.map (fun (uid, gid, groups) -> Some uid, gid, groups)
                    |> Option.defaultValue (None, 0, Set.empty)
                ensureConnectionResourcesExternal request state connectionUid connectionGroups (Some journal)
                let mutable current = journal
                for KeyValue(name, record) in journal.Users do
                    current <- cleanupUserAccess environment connectionUid request.ConnectionUser current name record
                    current <- withoutUserUserRecord current name
                    persistJournal environment current
                // Identity and groups are retained on resource deletion.
                current <- { current with Groups = Map.empty }
                persistJournal environment current
                state <- parseLocalState environment
                ensureConnectionTransport environment state request.ConnectionUser
                removeJournal environment request.ResourceId
                let bounds = readBounds environment
                let actual = createActual environment bounds state Map.empty journal.Users request.Groups request.Users
                envelope false true actual

    let handle (environment: HostEnvironment) (request: JsonElement) : JsonNode =
        try
            if not (OperatingSystem.IsLinux()) then raise (PlatformNotSupportedException("The Users helper requires Linux."))
            let parsed = parseRequest request
            match parsed.Operation with
            | "read" -> readOperation environment parsed
            | "apply" -> applyOperation environment parsed
            | "delete" -> deleteOperation environment parsed
            | _ -> fail "unsupported Users operation"
        with
        | :? BackendError -> reraise ()
        | :? PlatformNotSupportedException -> reraise ()
        | _ -> fail "Users operation failed because the host state could not be safely observed or changed"
