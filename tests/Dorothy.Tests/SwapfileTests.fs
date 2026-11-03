namespace Dorothy.Tests

open System
open System.Collections.Generic
open System.IO
open System.Security.Cryptography
open System.Runtime.InteropServices
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Collections.Immutable
open System.Threading
open Dorothy.DSL.Provider
open Pulumi.Experimental
open Pulumi.Experimental.Provider
open Dorothy.HostHelper
open NUnit.Framework

[<RequireQualifiedAccess>]
module private SwapfileTestNative =
    [<DllImport("libc", EntryPoint = "chown", SetLastError = true)>]
    extern int private nativeChown (string path, uint32 owner, uint32 group)

    [<DllImport("libc", EntryPoint = "geteuid")>]
    extern uint32 private nativeGetEffectiveUserId ()

    let changeOwner (path: string) (owner: uint32) (group: uint32) = nativeChown(path, owner, group)
    let effectiveUserId () = nativeGetEffectiveUserId ()

[<Sealed>]
type private SwapfileFakeHost(root: string) =
    let calls = ResizeArray<string * string list>()
    let activePaths = HashSet<string>(StringComparer.Ordinal)
    let enabledUnits = HashSet<string>(StringComparer.Ordinal)
    let mutable failNextEnableNow = false
    let mutable leaveActiveOnStop = false
    let preparationVisibility = ResizeArray<bool * bool>()
    let activationVisibility = ResizeArray<bool * bool>()
    let mutable observedStatePath: string option = None
    let mutable lastLogicalPath: string option = None
    let mutable failNextMkswap = false



    let mappedPath (logicalPath: string) =
        Path.Combine(root, logicalPath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar))

    let unitPath name = mappedPath ("/etc/systemd/system/" + name)

    let unitWhat name =
        let path = unitPath name
        if not (File.Exists path) then invalidOp ("Fake systemd unit does not exist: " + name)
        File.ReadAllLines(path)
        |> Array.tryPick (fun line -> if line.StartsWith("What=", StringComparison.Ordinal) then Some(line.Substring(5)) else None)
        |> Option.defaultWith (fun () -> invalidOp ("Fake systemd unit has no What= path: " + name))

    let observePreparation () =
        match observedStatePath, lastLogicalPath with
        | Some statePath, Some logicalPath ->
            preparationVisibility.Add((File.Exists(mappedPath logicalPath), File.Exists statePath))
        | _ -> ()

    let observeActivation name =
        match observedStatePath with
        | Some statePath -> activationVisibility.Add((File.Exists(mappedPath (unitWhat name)), File.Exists statePath))
        | None -> ()

    let escapedUnitName (logicalPath: string) =
        let segments =
            logicalPath.TrimStart('/').Split([| '/' |], StringSplitOptions.RemoveEmptyEntries)
            |> Array.map (fun segment -> segment.Replace("-", "\\x2d", StringComparison.Ordinal))
        String.concat "-" segments + ".swap"

    let success stdout = { ExitCode = 0; Stdout = stdout; Stderr = "" }
    let failure message = { ExitCode = 99; Stdout = ""; Stderr = message }

    let run executable arguments _ =
        calls.Add((executable, arguments))
        match executable, arguments with
        | "systemd-escape", [ "--path"; "--suffix=swap"; logicalPath ] ->
            lastLogicalPath <- Some logicalPath
            success (escapedUnitName logicalPath + "\n")
        | "fallocate", [ "-l"; size; "--"; path ] ->
            observePreparation ()
            try
                use file = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None)
                let requestedSize = Int64.Parse(size)
                if requestedSize > file.Length then file.SetLength(requestedSize)
                success ""
            with error -> failure error.Message
        | "mkswap", [ "--"; _ ] ->
            observePreparation ()
            if failNextMkswap then
                failNextMkswap <- false
                failure "injected mkswap failure"
            else success ""
        | "swapon", [ "--show=NAME"; "--noheadings"; "--raw" ] ->
            activePaths |> Seq.sort |> String.concat "\n" |> fun output -> if output = "" then success "" else success (output + "\n")
        | "swapoff", [ "--"; path ] ->
            activePaths.Remove(path) |> ignore
            success ""
        | "systemctl", [ "show"; "--no-pager"; "--property=LoadState"; "--property=UnitFileState"; "--property=ActiveState"; name ] ->
            let exists = File.Exists(unitPath name)
            let logicalPath =
                if exists then
                    File.ReadAllLines(unitPath name)
                    |> Array.tryPick (fun line -> if line.StartsWith("What=", StringComparison.Ordinal) then Some(line.Substring(5)) else None)
                else None
            let path = logicalPath |> Option.map mappedPath |> Option.defaultValue ""
            let isActive = exists && activePaths.Contains(path)
            let state = if exists then "loaded" else "not-found"
            let enabled = if exists && enabledUnits.Contains(name) then "enabled" else "disabled"
            let active = if isActive then "active" else "inactive"
            success ("LoadState=" + state + "\nUnitFileState=" + enabled + "\nActiveState=" + active + "\n")
        | "systemctl", [ "daemon-reload" ] -> success ""
        | "systemctl", [ "enable"; "--now"; name ] when failNextEnableNow ->
            failNextEnableNow <- false
            failure "injected activation failure"
        | "systemctl", [ "enable"; "--now"; name ] ->
            observeActivation name
            enabledUnits.Add(name) |> ignore
            activePaths.Add(mappedPath (unitWhat name)) |> ignore
            success ""
        | "systemctl", [ "enable"; name ] ->
            enabledUnits.Add(name) |> ignore
            success ""
        | "systemctl", [ "disable"; "--now"; name ] ->
            enabledUnits.Remove(name) |> ignore
            if not leaveActiveOnStop && File.Exists(unitPath name) then activePaths.Remove(mappedPath (unitWhat name)) |> ignore
            success ""
        | "systemctl", [ "disable"; name ] ->
            enabledUnits.Remove(name) |> ignore
            success ""
        | "systemctl", [ "restart"; name ] ->
            if File.Exists(unitPath name) then
                let path = mappedPath (unitWhat name)
                activePaths.Remove(path) |> ignore
                activePaths.Add(path) |> ignore
            success ""
        | "systemctl", [ "start"; name ] ->
            if File.Exists(unitPath name) then activePaths.Add(mappedPath (unitWhat name)) |> ignore
            success ""
        | "systemctl", [ "stop"; name ] ->
            if not leaveActiveOnStop && File.Exists(unitPath name) then activePaths.Remove(mappedPath (unitWhat name)) |> ignore
            success ""
        | _ -> failure ("unexpected fake host command: " + executable)

    do
        Directory.CreateDirectory(mappedPath "/etc/systemd/system") |> ignore
        Directory.CreateDirectory(mappedPath "/var") |> ignore

    member _.Environment = TestSupport.fakeHostEnvironment root run (fun () -> DateTimeOffset.UnixEpoch)
    member _.Calls = calls
    member _.ActivePaths = activePaths
    member _.ObserveStatePath(path: string) = observedStatePath <- Some path
    member _.PreparationVisibility = preparationVisibility.ToArray()
    member _.ActivationVisibility = activationVisibility.ToArray()
    member _.FailNextMkswap() = failNextMkswap <- true
    member _.MapPath(logicalPath: string) = mappedPath logicalPath
    member _.UnitPath(logicalPath: string) = unitPath (escapedUnitName logicalPath)
    member _.UnitName(logicalPath: string) = escapedUnitName logicalPath
    member _.FailNextEnableNow() = failNextEnableNow <- true
    member _.LeaveActiveOnStop() = leaveActiveOnStop <- true
    member _.AddUnrelatedActivePath(path: string) = activePaths.Add(path) |> ignore
    member _.SimulateInterruptedResize(logicalPath: string, sizeBytes: int64) =
        activePaths.Remove(mappedPath logicalPath) |> ignore
        use file = new FileStream(mappedPath logicalPath, FileMode.Open, FileAccess.Write, FileShare.None)
        file.SetLength(sizeBytes)

[<RequireQualifiedAccess>]
module private SwapfileTestHelpers =
    let owner = "urn:pulumi:test::test::dorothy:host:Swapfile::main"
    let size1 = 1048576L
    let size2 = 2097152L

    let ownerDigest =
        SHA256.HashData(Encoding.UTF8.GetBytes(owner))
        |> Convert.ToHexString
        |> fun value -> value.ToLowerInvariant()

    let statePath (host: SwapfileFakeHost) = host.MapPath("/var/lib/keroosha-iac/swapfiles/" + ownerDigest + ".json")

    let request (host: SwapfileFakeHost) (operation: string) (path: string) (sizeBytes: int64) =
        let body = JsonObject()
        body["operation"] <- JsonValue.Create(operation)
        body["ownerId"] <- JsonValue.Create(owner)
        body["path"] <- JsonValue.Create(path)
        body["sizeBytes"] <- JsonValue.Create(sizeBytes)
        use document = JsonDocument.Parse(body.ToJsonString())
        Swapfile.handle host.Environment document.RootElement

    let apply host path sizeBytes = request host "apply" path sizeBytes
    let read host path sizeBytes = request host "read" path sizeBytes
    let delete host path sizeBytes = request host "delete" path sizeBytes

    let getBool (response: JsonNode) (name: string) = response[name].GetValue<bool>()
    let getInt32 (response: JsonNode) (name: string) = response[name].GetValue<int>()
    let getInt64 (response: JsonNode) (name: string) = response[name].GetValue<int64>()
    let getString (response: JsonNode) (name: string) = response[name].GetValue<string>()

[<TestFixture>]
type SwapfileTests() =
    [<Test>]
    member _.``Create read and repeated apply are exact and idempotent``() =
        use temporary = new TemporaryDirectory("dorothy-swapfile-")
        let host = SwapfileFakeHost(temporary.Path)
        let path = "/var/swapfile"

        let before = SwapfileTestHelpers.read host path SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool before "owned", Is.False)
        Assert.That(SwapfileTestHelpers.getBool before "inSync", Is.False)
        Assert.That(File.Exists(host.MapPath(path)), Is.False)
        Assert.That(Directory.Exists(Path.GetDirectoryName(SwapfileTestHelpers.statePath host)), Is.False)

        let applied = SwapfileTestHelpers.apply host path SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool applied "owned", Is.True)
        Assert.That(SwapfileTestHelpers.getBool applied "inSync", Is.True)
        Assert.That(SwapfileTestHelpers.getBool applied "enabled", Is.True)
        Assert.That(SwapfileTestHelpers.getBool applied "active", Is.True)
        Assert.That(SwapfileTestHelpers.getString applied "actualPath", Is.EqualTo(path))
        Assert.That(SwapfileTestHelpers.getInt64 applied "actualSizeBytes", Is.EqualTo(SwapfileTestHelpers.size1))

        let target = host.MapPath(path)
        Assert.That(File.Exists(target), Is.True)
        Assert.That(File.GetUnixFileMode(target), Is.EqualTo(UnixFileMode.UserRead ||| UnixFileMode.UserWrite))
        Assert.That(File.GetUnixFileMode(SwapfileTestHelpers.statePath host), Is.EqualTo(UnixFileMode.UserRead ||| UnixFileMode.UserWrite))
        let unitFile = host.UnitPath(path)
        Assert.That(File.Exists(unitFile), Is.True)
        Assert.That(File.ReadAllText(unitFile), Does.Contain("# Dorothy owner-sha256=" + SwapfileTestHelpers.ownerDigest))
        Assert.That(File.ReadAllText(unitFile), Does.Contain("What=" + path))
        Assert.That(host.Calls |> Seq.exists (fun (executable, arguments) -> executable = "systemd-escape" && arguments = [ "--path"; "--suffix=swap"; path ]), Is.True)
        Assert.That(Path.GetFileName(unitFile), Is.EqualTo("var-swapfile.swap"))

        let fallocateCount () = host.Calls |> Seq.filter (fun (executable, _) -> executable = "fallocate") |> Seq.length
        let mkswapCount () = host.Calls |> Seq.filter (fun (executable, _) -> executable = "mkswap") |> Seq.length
        let allocationsBeforeRepeat = fallocateCount ()
        let signaturesBeforeRepeat = mkswapCount ()
        let read = SwapfileTestHelpers.read host path SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool read "inSync", Is.True)
        let repeated = SwapfileTestHelpers.apply host path SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool repeated "inSync", Is.True)
        Assert.That(fallocateCount (), Is.EqualTo(allocationsBeforeRepeat))
        Assert.That(mkswapCount (), Is.EqualTo(signaturesBeforeRepeat))


    [<Test>]
    member _.``Failed anonymous preparation keeps the final path absent until ownership is journaled``() =
        use temporary = new TemporaryDirectory("dorothy-swapfile-preparation-")
        let host = SwapfileFakeHost(temporary.Path)
        let path = "/var/prepared-swapfile"
        let target = host.MapPath(path)
        let stateFile = SwapfileTestHelpers.statePath host
        host.ObserveStatePath(stateFile)
        host.FailNextMkswap()

        let failedApply = TestDelegate(fun () -> SwapfileTestHelpers.apply host path SwapfileTestHelpers.size1 |> ignore)
        Assert.Throws<Swapfile.BackendError>(failedApply) |> ignore
        Assert.That(File.Exists(target), Is.False)
        Assert.That(File.Exists(stateFile), Is.False)
        Assert.That(host.PreparationVisibility.Length, Is.EqualTo(2))
        Assert.That(
            host.PreparationVisibility |> Array.forall (fun (pathVisible, journalVisible) -> not pathVisible && not journalVisible),
            Is.True)

        let applied = SwapfileTestHelpers.apply host path SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool applied "inSync", Is.True)
        Assert.That(File.Exists(target), Is.True)
        Assert.That(File.Exists(stateFile), Is.True)
        Assert.That(host.PreparationVisibility.Length, Is.EqualTo(4))
        Assert.That(
            host.PreparationVisibility |> Array.forall (fun (pathVisible, journalVisible) -> not pathVisible && not journalVisible),
            Is.True)
        let activation = host.ActivationVisibility
        Assert.That(activation.Length, Is.EqualTo(1))
        Assert.That(activation[0], Is.EqualTo((true, true)))

    [<Test>]
    member _.``Apply repairs swapfile mode drift``() =
        use temporary = new TemporaryDirectory("dorothy-swapfile-mode-")
        let host = SwapfileFakeHost(temporary.Path)
        let path = "/var/swapfile"
        SwapfileTestHelpers.apply host path SwapfileTestHelpers.size1 |> ignore
        File.SetUnixFileMode(host.MapPath(path), UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.GroupRead)

        let drift = SwapfileTestHelpers.read host path SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool drift "inSync", Is.False)
        Assert.That(SwapfileTestHelpers.getInt32 drift "mode", Is.EqualTo(0o640))
        let repaired = SwapfileTestHelpers.apply host path SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool repaired "inSync", Is.True)
        Assert.That(File.GetUnixFileMode(host.MapPath(path)), Is.EqualTo(UnixFileMode.UserRead ||| UnixFileMode.UserWrite))

    [<Test>]
    member _.``Resize updates the owned inode in place and activates the exact file size``() =
        use temporary = new TemporaryDirectory("dorothy-swapfile-resize-")
        let host = SwapfileFakeHost(temporary.Path)
        let path = "/var/swapfile"
        SwapfileTestHelpers.apply host path SwapfileTestHelpers.size1 |> ignore
        let oldTarget = host.MapPath(path)
        let oldUnit = host.UnitPath(path)
        let enabledBefore = host.Calls.Count
        host.LeaveActiveOnStop()
        let resized = SwapfileTestHelpers.apply host path SwapfileTestHelpers.size2

        Assert.That(SwapfileTestHelpers.getBool resized "inSync", Is.True)
        Assert.That(FileInfo(oldTarget).Length, Is.EqualTo(SwapfileTestHelpers.size2))
        Assert.That(host.ActivePaths.Contains(oldTarget), Is.True)
        Assert.That(Directory.GetFiles(Path.GetDirectoryName oldTarget), Is.EquivalentTo([| oldTarget |]))
        Assert.That(File.Exists(oldUnit), Is.True)
        Assert.That(host.Calls |> Seq.skip enabledBefore |> Seq.exists (fun (executable, arguments) -> executable = "systemctl" && arguments = [ "stop"; host.UnitName(path) ]), Is.True)
        Assert.That(host.Calls |> Seq.skip enabledBefore |> Seq.exists (fun (executable, arguments) -> executable = "systemctl" && arguments = [ "enable"; "--now"; host.UnitName(path) ]), Is.True)
        Assert.That(host.Calls |> Seq.skip enabledBefore |> Seq.exists (fun (executable, arguments) -> executable = "swapoff" && arguments = [ "--"; oldTarget ]), Is.True)
        let shrunk = SwapfileTestHelpers.apply host path SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool shrunk "inSync", Is.True)
        Assert.That(FileInfo(oldTarget).Length, Is.EqualTo(SwapfileTestHelpers.size1))
        Assert.That(host.ActivePaths.Contains(oldTarget), Is.True)
        Assert.That(File.GetUnixFileMode(oldTarget), Is.EqualTo(UnixFileMode.UserRead ||| UnixFileMode.UserWrite))

    [<Test>]
    member _.``Interrupted resize resumes from persisted inode ownership``() =
        use temporary = new TemporaryDirectory("dorothy-swapfile-resize-recovery-")
        let host = SwapfileFakeHost(temporary.Path)
        let path = "/var/swapfile"
        SwapfileTestHelpers.apply host path SwapfileTestHelpers.size1 |> ignore

        host.SimulateInterruptedResize(path, SwapfileTestHelpers.size2)
        let interrupted = SwapfileTestHelpers.read host path SwapfileTestHelpers.size2
        Assert.That(SwapfileTestHelpers.getBool interrupted "owned", Is.True)
        Assert.That(SwapfileTestHelpers.getBool interrupted "active", Is.False)
        Assert.That(SwapfileTestHelpers.getBool interrupted "inSync", Is.False)
        Assert.That(SwapfileTestHelpers.getInt64 interrupted "actualSizeBytes", Is.EqualTo(SwapfileTestHelpers.size2))

        let recovered = SwapfileTestHelpers.apply host path SwapfileTestHelpers.size2
        Assert.That(SwapfileTestHelpers.getBool recovered "inSync", Is.True)
        Assert.That(SwapfileTestHelpers.getBool recovered "active", Is.True)
        Assert.That(FileInfo(host.MapPath(path)).Length, Is.EqualTo(SwapfileTestHelpers.size2))

    [<Test>]
    member _.``Writable swapfile parent directories are rejected before allocation``() =
        use temporary = new TemporaryDirectory("dorothy-swapfile-writable-parent-")
        let host = SwapfileFakeHost(temporary.Path)
        let parent = host.MapPath("/var/writable")
        Directory.CreateDirectory(parent) |> ignore
        File.SetUnixFileMode(parent, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute ||| UnixFileMode.GroupWrite)

        let action = TestDelegate(fun () -> SwapfileTestHelpers.apply host "/var/writable/swapfile" SwapfileTestHelpers.size1 |> ignore)
        Assert.Throws<Swapfile.BackendError>(action) |> ignore
        Assert.That(File.Exists(host.MapPath("/var/writable/swapfile")), Is.False)
        Assert.That(host.Calls |> Seq.exists (fun (executable, _) -> executable = "fallocate"), Is.False)

    [<Test>]
    member _.``Swapfile parent directories must share the mapped root owner``() =
        if not (OperatingSystem.IsLinux()) || SwapfileTestNative.effectiveUserId() <> 0u then
            Assert.Ignore("The ownership-boundary test requires root on Linux.")
        use temporary = new TemporaryDirectory("dorothy-swapfile-owner-parent-")
        let host = SwapfileFakeHost(temporary.Path)
        let parent = host.MapPath("/var/nonroot")
        Directory.CreateDirectory(parent) |> ignore
        if SwapfileTestNative.changeOwner parent 65534u 65534u <> 0 then
            Assert.Ignore("The test process cannot change the temporary directory owner.")

        let action = TestDelegate(fun () -> SwapfileTestHelpers.apply host "/var/nonroot/swapfile" SwapfileTestHelpers.size1 |> ignore)
        Assert.Throws<Swapfile.BackendError>(action) |> ignore
        Assert.That(File.Exists(host.MapPath("/var/nonroot/swapfile")), Is.False)

    [<Test>]
    member _.``Path change activates the new unit before retiring the old owned path``() =
        use temporary = new TemporaryDirectory("dorothy-swapfile-path-")
        let host = SwapfileFakeHost(temporary.Path)
        let oldPath = "/var/swapfile"
        let newPath = "/var/swapsecond"
        let oldUnit = host.UnitPath(oldPath)
        let newUnit = host.UnitPath(newPath)
        SwapfileTestHelpers.apply host oldPath SwapfileTestHelpers.size1 |> ignore
        host.AddUnrelatedActivePath("/dev/unrelated-swap")

        let changed = SwapfileTestHelpers.apply host newPath SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool changed "inSync", Is.True)
        Assert.That(File.Exists(host.MapPath(oldPath)), Is.False)
        Assert.That(File.Exists(host.MapPath(newPath)), Is.True)
        Assert.That(File.Exists(oldUnit), Is.False)
        Assert.That(File.Exists(newUnit), Is.True)
        Assert.That(host.ActivePaths.Contains(host.MapPath(newPath)), Is.True)
        Assert.That(host.ActivePaths.Contains("/dev/unrelated-swap"), Is.True)

        let activationIndex =
            host.Calls
            |> Seq.tryFindIndex (fun (executable, arguments) -> executable = "systemctl" && arguments = [ "enable"; "--now"; host.UnitName(newPath) ])
            |> Option.get
        let retiredUnitRemoveIndex = host.Calls |> Seq.findIndex (fun (executable, arguments) -> executable = "systemctl" && arguments = [ "disable"; "--now"; host.UnitName(oldPath) ])
        Assert.That(activationIndex, Is.LessThan(retiredUnitRemoveIndex))

        host.LeaveActiveOnStop()
        let deleted = SwapfileTestHelpers.delete host newPath SwapfileTestHelpers.size1
        Assert.That(host.Calls |> Seq.exists (fun (executable, arguments) -> executable = "swapoff" && arguments = [ "--"; host.MapPath(newPath) ]), Is.True)
        Assert.That(deleted.AsObject().Count, Is.Zero)
        Assert.That(File.Exists(host.MapPath(newPath)), Is.False)
        Assert.That(File.Exists(newUnit), Is.False)
        Assert.That(File.Exists(SwapfileTestHelpers.statePath host), Is.False)
        Assert.That(host.ActivePaths.Contains("/dev/unrelated-swap"), Is.True)
        SwapfileTestHelpers.delete host newPath SwapfileTestHelpers.size1 |> ignore

    [<Test>]
    member _.``Interrupted path activation persists ownership and retries safely``() =
        use temporary = new TemporaryDirectory("dorothy-swapfile-path-recovery-")
        let host = SwapfileFakeHost(temporary.Path)
        let oldPath = "/var/swapfile"
        let newPath = "/var/swapsecond"
        SwapfileTestHelpers.apply host oldPath SwapfileTestHelpers.size1 |> ignore
        host.FailNextEnableNow()

        let interruptedAction = TestDelegate(fun () -> SwapfileTestHelpers.apply host newPath SwapfileTestHelpers.size1 |> ignore)
        Assert.Throws<Swapfile.BackendError>(interruptedAction) |> ignore
        Assert.That(File.Exists(host.MapPath(oldPath)), Is.True)
        Assert.That(File.Exists(host.MapPath(newPath)), Is.True)
        Assert.That(host.ActivePaths.Contains(host.MapPath(oldPath)), Is.True)
        Assert.That(host.ActivePaths.Contains(host.MapPath(newPath)), Is.False)

        let interrupted = SwapfileTestHelpers.read host oldPath SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool interrupted "owned", Is.True)
        Assert.That(SwapfileTestHelpers.getString interrupted "actualPath", Is.EqualTo(newPath))
        Assert.That(SwapfileTestHelpers.getBool interrupted "inSync", Is.False)

        let recovered = SwapfileTestHelpers.apply host newPath SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool recovered "inSync", Is.True)
        Assert.That(host.ActivePaths.Contains(host.MapPath(newPath)), Is.True)
        Assert.That(File.Exists(host.MapPath(oldPath)), Is.False)

    [<Test>]
    member _.``Failed resize rolls the owned file and activation back``() =
        use temporary = new TemporaryDirectory("dorothy-swapfile-rollback-")
        let host = SwapfileFakeHost(temporary.Path)
        let path = "/var/swapfile"
        SwapfileTestHelpers.apply host path SwapfileTestHelpers.size1 |> ignore
        host.FailNextEnableNow()

        let action = TestDelegate(fun () -> SwapfileTestHelpers.apply host path SwapfileTestHelpers.size2 |> ignore)
        Assert.Throws<Swapfile.BackendError>(action) |> ignore
        Assert.That(FileInfo(host.MapPath(path)).Length, Is.EqualTo(SwapfileTestHelpers.size1))
        Assert.That(host.ActivePaths.Contains(host.MapPath(path)), Is.True)
        Assert.That(Directory.GetFiles(Path.GetDirectoryName(host.MapPath(path))), Is.EquivalentTo([| host.MapPath(path) |]))
        let restored = SwapfileTestHelpers.read host path SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool restored "inSync", Is.True)

    [<Test>]
    member _.``Pre-existing target unit state and fstab claims are preserved``() =
        use targetTemporary = new TemporaryDirectory("dorothy-swapfile-target-collision-")
        let targetHost = SwapfileFakeHost(targetTemporary.Path)
        let path = "/var/swapfile"
        let target = targetHost.MapPath(path)
        File.WriteAllText(target, "unowned target")
        let targetAction = TestDelegate(fun () -> SwapfileTestHelpers.apply targetHost path SwapfileTestHelpers.size1 |> ignore)
        Assert.Throws<Swapfile.BackendError>(targetAction) |> ignore
        Assert.That(File.ReadAllText(target), Is.EqualTo("unowned target"))

        use unitTemporary = new TemporaryDirectory("dorothy-swapfile-unit-collision-")
        let unitHost = SwapfileFakeHost(unitTemporary.Path)
        let unit = unitHost.UnitPath(path)
        File.WriteAllText(unit, "unowned unit")
        let unitAction = TestDelegate(fun () -> SwapfileTestHelpers.apply unitHost path SwapfileTestHelpers.size1 |> ignore)
        Assert.Throws<Swapfile.BackendError>(unitAction) |> ignore
        Assert.That(File.ReadAllText(unit), Is.EqualTo("unowned unit"))
        Assert.That(File.Exists(unitHost.MapPath(path)), Is.False)

        use stateTemporary = new TemporaryDirectory("dorothy-swapfile-state-collision-")
        let stateHost = SwapfileFakeHost(stateTemporary.Path)
        let statePath = SwapfileTestHelpers.statePath stateHost
        Directory.CreateDirectory(Path.GetDirectoryName statePath) |> ignore
        File.WriteAllText(statePath, "unowned state")
        let stateAction = TestDelegate(fun () -> SwapfileTestHelpers.apply stateHost path SwapfileTestHelpers.size1 |> ignore)
        Assert.Throws<Swapfile.BackendError>(stateAction) |> ignore
        Assert.That(File.ReadAllText(statePath), Is.EqualTo("unowned state"))
        Assert.That(File.Exists(stateHost.MapPath(path)), Is.False)

        use fstabTemporary = new TemporaryDirectory("dorothy-swapfile-fstab-")
        let fstabHost = SwapfileFakeHost(fstabTemporary.Path)
        let fstab = fstabHost.MapPath("/etc/fstab")
        let fstabContent = path + " none swap sw 0 0\n"
        File.WriteAllText(fstab, fstabContent)
        let fstabAction = TestDelegate(fun () -> SwapfileTestHelpers.apply fstabHost path SwapfileTestHelpers.size1 |> ignore)
        Assert.Throws<Swapfile.BackendError>(fstabAction) |> ignore
        Assert.That(File.ReadAllText(fstab), Is.EqualTo(fstabContent))
        Assert.That(File.Exists(fstabHost.MapPath(path)), Is.False)

        use managedTemporary = new TemporaryDirectory("dorothy-swapfile-fstab-managed-")
        let managedHost = SwapfileFakeHost(managedTemporary.Path)
        let managedPath = "/var/swapfile"
        SwapfileTestHelpers.apply managedHost managedPath SwapfileTestHelpers.size1 |> ignore
        let managedFstab = managedHost.MapPath("/etc/fstab")
        let managedFstabContent = managedPath + " none swap sw 0 0\n"
        File.WriteAllText(managedFstab, managedFstabContent)
        let conflicted = SwapfileTestHelpers.read managedHost managedPath SwapfileTestHelpers.size1
        Assert.That(SwapfileTestHelpers.getBool conflicted "inSync", Is.False)
        let removeClaimedAction = TestDelegate(fun () -> SwapfileTestHelpers.delete managedHost managedPath SwapfileTestHelpers.size1 |> ignore)
        let moveClaimedAction = TestDelegate(fun () -> SwapfileTestHelpers.apply managedHost "/var/swapsecond" SwapfileTestHelpers.size1 |> ignore)
        Assert.Throws<Swapfile.BackendError>(removeClaimedAction) |> ignore
        Assert.Throws<Swapfile.BackendError>(moveClaimedAction) |> ignore
        Assert.That(File.Exists(managedHost.MapPath(managedPath)), Is.True)
        Assert.That(File.Exists(managedHost.UnitPath(managedPath)), Is.True)
        Assert.That(managedHost.ActivePaths.Contains(managedHost.MapPath(managedPath)), Is.True)
        Assert.That(File.ReadAllText(managedFstab), Is.EqualTo(managedFstabContent))

    [<Test>]
    member _.``Target and parent symlinks are rejected without following or deleting their targets``() =
        if not (OperatingSystem.IsLinux()) then Assert.Ignore("Swapfile helper safety tests require Linux.")
        use temporary = new TemporaryDirectory("dorothy-swapfile-symlink-")
        let host = SwapfileFakeHost(temporary.Path)
        let target = host.MapPath("/var/real-target")
        File.WriteAllText(target, "keep me")
        let link = host.MapPath("/var/swapfile")
        File.CreateSymbolicLink(link, target) |> ignore
        let targetAction = TestDelegate(fun () -> SwapfileTestHelpers.apply host "/var/swapfile" SwapfileTestHelpers.size1 |> ignore)
        Assert.Throws<Swapfile.BackendError>(targetAction) |> ignore
        Assert.That(File.ReadAllText(target), Is.EqualTo("keep me"))
        Assert.That(File.GetAttributes(link).HasFlag(FileAttributes.ReparsePoint), Is.True)
        File.Delete(link)
        SwapfileTestHelpers.apply host "/var/swapfile" SwapfileTestHelpers.size1 |> ignore
        let newPath = "/var/swapsecond"
        let newLink = host.MapPath(newPath)
        File.CreateSymbolicLink(newLink, target) |> ignore
        let pathChange = TestDelegate(fun () -> SwapfileTestHelpers.apply host newPath SwapfileTestHelpers.size1 |> ignore)
        Assert.Throws<Swapfile.BackendError>(pathChange) |> ignore
        Assert.That(File.Exists(host.MapPath("/var/swapfile")), Is.True)
        Assert.That(host.ActivePaths.Contains(host.MapPath("/var/swapfile")), Is.True)
        Assert.That(File.ReadAllText(target), Is.EqualTo("keep me"))
        Assert.That(File.GetAttributes(newLink).HasFlag(FileAttributes.ReparsePoint), Is.True)


        let outside = host.MapPath("/outside")
        Directory.CreateDirectory(outside) |> ignore
        let parentLink = host.MapPath("/linked-parent")
        Directory.CreateSymbolicLink(parentLink, outside) |> ignore
        let parentAction = TestDelegate(fun () -> SwapfileTestHelpers.apply host "/linked-parent/swapfile" SwapfileTestHelpers.size1 |> ignore)
        Assert.Throws<Swapfile.BackendError>(parentAction) |> ignore
        Assert.That(Directory.GetFiles(outside), Is.Empty)

[<RequireQualifiedAccess>]
module private SwapfileProviderTestValues =
    let private resourceToken = "keroosha:debian:Swapfile"

    let private map (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do builder.Add(key, value)
        PropertyValue(builder.ToImmutable())

    let private inputMap (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do builder.Add(key, value)
        builder.ToImmutable()

    let private string (value: string) = PropertyValue(value)
    let private number (value: int) = PropertyValue(float value)
    let boolean (value: bool) = PropertyValue(value)

    let private requestUrn name =
        Pulumi.Urn(sprintf "urn:pulumi:unit::unit::%s::%s" resourceToken name)

    let input path sizeMiB =
        inputMap [
            "connection",
            map [
                "address", string "192.0.2.1"
                "user", string "root"
            ]
            "path", string path
            "sizeMiB", number sizeMiB
        ]

    let check (provider: DorothyProvider) inputs =
        let request =
            CheckRequest(
                requestUrn "swapfile-check",
                ImmutableDictionary<string, PropertyValue>.Empty,
                inputs,
                ImmutableArray<byte>.Empty
            )
        provider.Check(request, CancellationToken.None).GetAwaiter().GetResult()

    let create (provider: DorothyProvider) inputs =
        let request = CreateRequest(requestUrn "swapfile-preview", inputs, TimeSpan.FromSeconds(1.0), true)
        provider.Create(request, CancellationToken.None).GetAwaiter().GetResult()

    let diff (provider: DorothyProvider) id oldInputs oldOutputs newInputs =
        let request =
            DiffRequest(
                requestUrn "swapfile-diff",
                id,
                oldOutputs,
                newInputs,
                ImmutableArray<string>.Empty,
                oldInputs
            )
        provider.Diff(request, CancellationToken.None).GetAwaiter().GetResult()

    let outputs (entries: seq<string * PropertyValue>) = inputMap entries

[<TestFixture>]
type SwapfileProviderTests() =
    [<Test>]
    member _.``Provider Check validates swapfile path and measured size without host access``() =
        let provider = DorothyProvider()
        let valid = SwapfileProviderTestValues.input "/swapfile" 64
        let checkedInputs = SwapfileProviderTestValues.check provider valid
        let invalidPath =
            SwapfileProviderTestValues.check provider (SwapfileProviderTestValues.input "/tmp/../swapfile" 64)
        let invalidSize = SwapfileProviderTestValues.check provider (SwapfileProviderTestValues.input "/swapfile" 0)

        Assert.That(checkedInputs.Failures, Is.Empty)
        Assert.That(invalidPath.Failures |> Seq.exists (fun failure -> failure.Property = "path"), Is.True)
        Assert.That(invalidSize.Failures |> Seq.exists (fun failure -> failure.Property = "sizeMiB"), Is.True)

        let preview = SwapfileProviderTestValues.create provider valid
        Assert.That(preview.Id, Is.Empty)
        Assert.That(preview.Outputs["inSync"].IsComputed, Is.True)

    [<Test>]
    member _.``Provider Diff applies safe path and size updates and repairs activation drift``() =
        let provider = DorothyProvider()
        let oldInputs = SwapfileProviderTestValues.input "/swapfile" 64
        let newInputs = SwapfileProviderTestValues.input "/var/swapfile" 128
        let oldOutputs =
            SwapfileProviderTestValues.outputs [
                "owned", SwapfileProviderTestValues.boolean true
                "actualPath", PropertyValue("/swapfile")
                "actualSizeBytes", PropertyValue(float (64 * 1024 * 1024))
                "mode", PropertyValue(384.0)
                "enabled", SwapfileProviderTestValues.boolean true
                "active", SwapfileProviderTestValues.boolean true
                "inSync", SwapfileProviderTestValues.boolean true
            ]
        let unchanged = SwapfileProviderTestValues.diff provider "owned-id" oldInputs oldOutputs oldInputs
        let updated = SwapfileProviderTestValues.diff provider "owned-id" oldInputs oldOutputs newInputs
        let activationDrift =
            SwapfileProviderTestValues.diff
                provider
                "owned-id"
                oldInputs
                (SwapfileProviderTestValues.outputs [
                    "owned", SwapfileProviderTestValues.boolean true
                    "actualPath", PropertyValue("/swapfile")
                    "actualSizeBytes", PropertyValue(float (64 * 1024 * 1024))
                    "mode", PropertyValue(384.0)
                    "enabled", SwapfileProviderTestValues.boolean true
                    "active", SwapfileProviderTestValues.boolean false
                    "inSync", SwapfileProviderTestValues.boolean false
                ])
                oldInputs

        Assert.That(updated.Changes.Value, Is.True)
        Assert.That(unchanged.Changes.Value, Is.False)
        Assert.That(updated.Diffs.Contains("path"), Is.True)
        Assert.That(updated.Diffs.Contains("sizeMiB"), Is.True)
        Assert.That(updated.Replaces, Is.Empty)
        Assert.That(activationDrift.Changes.Value, Is.True)
        Assert.That(activationDrift.Diffs.Contains("inSync"), Is.True)
