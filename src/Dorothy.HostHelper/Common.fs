namespace Dorothy.HostHelper

open System
open System.ComponentModel
open System.Diagnostics
open System.IO
open System.Runtime.InteropServices
open System.Threading
open Microsoft.Win32.SafeHandles

type CommandResult =
    { ExitCode: int
      Stdout: string
      Stderr: string }

type HostEnvironment =
    { Root: string
      Run: string -> string list -> string option -> CommandResult
      UtcNow: unit -> DateTimeOffset }

type HostPrerequisiteError(message: string) =
    inherit Exception(message)

module HostEnvironment =
    let path (environment: HostEnvironment) (logicalPath: string) =
        if String.IsNullOrWhiteSpace environment.Root then
            invalidArg "environment" "The host environment root must not be empty."

        if String.IsNullOrWhiteSpace logicalPath || not (Path.IsPathRooted logicalPath) then
            invalidArg "logicalPath" "Host paths must be absolute logical paths."

        let root = Path.GetFullPath environment.Root
        let normalizedRoot = Path.TrimEndingDirectorySeparator root
        let normalizedLogicalPath = Path.GetFullPath logicalPath

        if normalizedRoot = Path.GetPathRoot normalizedRoot then
            normalizedLogicalPath
        else
            let relativePath =
                normalizedLogicalPath.TrimStart([| Path.DirectorySeparatorChar; Path.AltDirectorySeparatorChar |])
            let resolvedPath = Path.GetFullPath(Path.Combine(normalizedRoot, relativePath))
            let rootPrefix = normalizedRoot + string Path.DirectorySeparatorChar

            if resolvedPath <> normalizedRoot
               && not (resolvedPath.StartsWith(rootPrefix, StringComparison.Ordinal)) then
                invalidArg "logicalPath" "The host path escapes the mapped environment root."

            resolvedPath

    let private runProcess (fileName: string) (arguments: string list) (standardInput: string option) =
        if String.IsNullOrWhiteSpace fileName then
            invalidArg "fileName" "The executable path must not be empty."

        let startInfo = ProcessStartInfo()
        startInfo.FileName <- fileName
        startInfo.UseShellExecute <- false
        startInfo.RedirectStandardInput <- true
        startInfo.RedirectStandardOutput <- true
        startInfo.RedirectStandardError <- true
        startInfo.CreateNoWindow <- true
        startInfo.Environment["LC_ALL"] <- "C"
        startInfo.Environment["LANG"] <- "C"
        startInfo.Environment["DEBIAN_FRONTEND"] <- "noninteractive"
        startInfo.Environment["APT_LISTCHANGES_FRONTEND"] <- "none"

        for argument in arguments do
            if isNull argument then
                invalidArg "arguments" "Executable arguments must not contain null values."

            startInfo.ArgumentList.Add(argument)

        use childProcess = new Process()
        childProcess.StartInfo <- startInfo

        if not (childProcess.Start()) then
            raise (InvalidOperationException("The host command did not start."))

        let stdoutTask = childProcess.StandardOutput.ReadToEndAsync()
        let stderrTask = childProcess.StandardError.ReadToEndAsync()

        try
            try
                match standardInput with
                | Some input ->
                    childProcess.StandardInput.Write(input)
                    childProcess.StandardInput.Flush()
                | None -> ()
            with :? IOException ->
                // A command that exits before consuming stdin will report its own exit status below.
                ()
        finally
            childProcess.StandardInput.Close()

        childProcess.WaitForExit()
        let stdout = stdoutTask.GetAwaiter().GetResult()
        let stderr = stderrTask.GetAwaiter().GetResult()

        { ExitCode = childProcess.ExitCode
          Stdout = stdout
          Stderr = stderr }

    let system: HostEnvironment =
        { Root = "/"
          Run = runProcess
          UtcNow = fun () -> DateTimeOffset.UtcNow }

[<Struct; StructLayout(LayoutKind.Sequential, Size = 256)>]
type private LinuxStatx =
    val mutable Mask: uint32
    val mutable BlockSize: uint32
    val mutable Attributes: uint64
    val mutable LinkCount: uint32
    val mutable UserId: uint32
    val mutable GroupId: uint32
    val mutable Mode: uint16

module HostFiles =
    [<DllImport("libc", EntryPoint = "statx", SetLastError = true)>]
    extern int private nativeStatx (int directoryFileDescriptor, string path, int flags, uint32 mask, LinuxStatx& result)

    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int private nativeOpen (string path, int flags, int mode)

    [<DllImport("libc", EntryPoint = "fsync", SetLastError = true)>]
    extern int private nativeFsync (int fileDescriptor)

    [<DllImport("libc", EntryPoint = "close", SetLastError = true)>]
    extern int private nativeClose (int fileDescriptor)

    [<DllImport("libc", EntryPoint = "flock", SetLastError = true)>]
    extern int private nativeFlock (int fileDescriptor, int operation)

    let private ensureLinux () =
        if not (OperatingSystem.IsLinux()) then
            raise (PlatformNotSupportedException("The native host helper requires Linux."))

    let private fileTypeAtPath (path: string) =
        let mutable stat = Unchecked.defaultof<LinuxStatx>
        let result = nativeStatx(-100, path, 0x100, 0x1u, &stat)

        if result = 0 then
            Some(stat.Mode &&& 0xF000us)
        else
            let errorCode = Marshal.GetLastWin32Error()

            if errorCode = 2 then
                None
            else
                raise (Win32Exception(errorCode, "Could not inspect filesystem path '" + path + "'."))

    let private requireDirectory (path: string) =
        match fileTypeAtPath path with
        | Some fileType when fileType = 0x4000us -> ()
        | Some _ -> raise (IOException("Filesystem parent '" + path + "' is not a real directory."))
        | None -> raise (DirectoryNotFoundException("Filesystem parent '" + path + "' does not exist."))

    let private requireRegularOrAbsent (path: string) =
        match fileTypeAtPath path with
        | Some fileType when fileType = 0x8000us -> ()
        | Some _ -> raise (IOException("Refusing to replace non-regular filesystem object '" + path + "'."))
        | None -> ()

    let private syncDirectory (path: string) =
        // Linux flags: O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW.
        let descriptor = nativeOpen(path, 0x10000 ||| 0x80000 ||| 0x20000, 0)

        if descriptor < 0 then
            let errorCode = Marshal.GetLastWin32Error()
            raise (Win32Exception(errorCode, "Could not open directory '" + path + "' for synchronization."))

        try
            if nativeFsync descriptor <> 0 then
                let errorCode = Marshal.GetLastWin32Error()
                raise (Win32Exception(errorCode, "Could not synchronize directory '" + path + "'."))
        finally
            nativeClose descriptor |> ignore

    let atomicWrite (path: string) (contents: byte array) (mode: UnixFileMode) =
        ensureLinux ()

        if String.IsNullOrWhiteSpace path || not (Path.IsPathRooted path) then
            invalidArg "path" "Atomic-write paths must be absolute."

        if isNull contents then
            nullArg "contents"

        let fullPath = Path.GetFullPath path
        let parent = Path.GetDirectoryName fullPath

        if String.IsNullOrEmpty parent then
            invalidArg "path" "Atomic-write paths must have a parent directory."

        requireDirectory parent
        requireRegularOrAbsent fullPath

        let temporaryPath = Path.Combine(parent, ".keroosha-iac-" + Guid.NewGuid().ToString("N"))
        let mutable temporaryExists = false

        try
            let options = FileStreamOptions()
            options.Mode <- FileMode.CreateNew
            options.Access <- FileAccess.Write
            options.Share <- FileShare.None
            options.BufferSize <- 4096
            options.Options <- FileOptions.WriteThrough
            options.UnixCreateMode <- Nullable<UnixFileMode>(mode)
            use output = new FileStream(temporaryPath, options)
            temporaryExists <- true
            File.SetUnixFileMode(temporaryPath, mode)
            output.Write(contents, 0, contents.Length)
            output.Flush(true)
            requireRegularOrAbsent fullPath
            File.Move(temporaryPath, fullPath, true)
            temporaryExists <- false

            syncDirectory parent
        finally
            if temporaryExists then
                try
                    File.Delete temporaryPath
                with _ -> ()

    /// Copies a readable stream through a same-directory temporary file before atomic replacement.
    /// Keeps the source open and preserves the previous destination when copying fails.
    let atomicWriteStream (path: string) (contents: Stream) (mode: UnixFileMode) =
        ensureLinux ()

        if String.IsNullOrWhiteSpace path || not (Path.IsPathRooted path) then
            invalidArg "path" "Atomic-write paths must be absolute."

        if isNull contents then
            nullArg "contents"

        if not contents.CanRead then
            invalidArg "contents" "Atomic-write streams must be readable."

        let fullPath = Path.GetFullPath path
        let parent = Path.GetDirectoryName fullPath

        if String.IsNullOrEmpty parent then
            invalidArg "path" "Atomic-write paths must have a parent directory."

        requireDirectory parent
        requireRegularOrAbsent fullPath

        let temporaryPath = Path.Combine(parent, ".keroosha-iac-" + Guid.NewGuid().ToString("N"))
        let mutable temporaryExists = false

        try
            let options = FileStreamOptions()
            options.Mode <- FileMode.CreateNew
            options.Access <- FileAccess.Write
            options.Share <- FileShare.None
            options.BufferSize <- 4096
            options.Options <- FileOptions.WriteThrough
            options.UnixCreateMode <- Nullable<UnixFileMode>(UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
            use output = new FileStream(temporaryPath, options)
            temporaryExists <- true
            contents.CopyTo(output, 65536)
            output.Flush(true)
            File.SetUnixFileMode(temporaryPath, mode)
            output.Flush(true)
            requireRegularOrAbsent fullPath
            File.Move(temporaryPath, fullPath, true)
            temporaryExists <- false
            syncDirectory parent
        finally
            if temporaryExists then
                try
                    File.Delete temporaryPath
                with _ -> ()

    let lockFile (path: string) : IDisposable =
        ensureLinux ()

        if String.IsNullOrWhiteSpace path || not (Path.IsPathRooted path) then
            invalidArg "path" "Lock paths must be absolute."

        let fullPath = Path.GetFullPath path
        let parent = Path.GetDirectoryName fullPath

        if String.IsNullOrEmpty parent then
            invalidArg "path" "Lock paths must have a parent directory."

        requireDirectory parent
        requireRegularOrAbsent fullPath

        // Linux open flags: O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW; mode 0600.
        let descriptor = nativeOpen(fullPath, 0x2 ||| 0x40 ||| 0x80000 ||| 0x20000, 0x180)

        if descriptor < 0 then
            let errorCode = Marshal.GetLastWin32Error()
            raise (Win32Exception(errorCode, "Could not open lock file '" + fullPath + "'."))

        let handle = new SafeFileHandle(nativeint descriptor, true)

        try
            let mutable stat = Unchecked.defaultof<LinuxStatx>
            let statResult = nativeStatx(descriptor, "", 0x1000, 0x1u, &stat)

            if statResult <> 0 then
                let errorCode = Marshal.GetLastWin32Error()
                raise (Win32Exception(errorCode, "Could not inspect lock file '" + fullPath + "'."))

            if (stat.Mode &&& 0xF000us) <> 0x8000us then
                raise (IOException("Refusing to lock non-regular filesystem object '" + fullPath + "'."))

            let startedAt = Stopwatch.GetTimestamp()
            let timeout = TimeSpan.FromSeconds 120.0
            let mutable acquired = false

            while not acquired && Stopwatch.GetElapsedTime(startedAt) < timeout do
                if nativeFlock(descriptor, 2 ||| 4) = 0 then
                    acquired <- true
                else
                    let errorCode = Marshal.GetLastWin32Error()

                    if errorCode = 11 then
                        Thread.Sleep(50)
                    elif errorCode <> 4 then
                        raise (Win32Exception(errorCode, "Could not acquire lock file '" + fullPath + "'."))

            if not acquired then
                raise (TimeoutException("Timed out waiting for lock file '" + fullPath + "'."))

            let mutable disposed = 0

            { new IDisposable with
                member _.Dispose() =
                    if Interlocked.Exchange(&disposed, 1) = 0 then
                        nativeFlock(descriptor, 8) |> ignore
                        handle.Dispose() }
        with _ ->
            handle.Dispose()
            reraise ()
