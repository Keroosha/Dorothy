namespace Dorothy.Tests

open System
open System.IO
open System.Text
open Dorothy.HostHelper
open NUnit.Framework

type private FailingReadStream() =
    inherit Stream()

    let mutable firstRead = true

    override _.CanRead = true
    override _.CanSeek = false
    override _.CanWrite = false
    override _.Length = raise (NotSupportedException())
    override _.Position
        with get () = raise (NotSupportedException())
        and set _ = raise (NotSupportedException())
    override _.Flush() = ()
    override _.Read(buffer: byte[], offset: int, count: int) =
        if firstRead then
            firstRead <- false
            let payload = Encoding.UTF8.GetBytes("partial replacement")
            let copied = min count payload.Length
            Array.Copy(payload, 0, buffer, offset, copied)
            copied
        else
            raise (IOException("simulated source read failure"))
    override _.Seek(_, _) = raise (NotSupportedException())
    override _.SetLength(_) = raise (NotSupportedException())
    override _.Write(_, _, _) = raise (NotSupportedException())

[<TestFixture>]
type NativeCoreTests() =
    [<Test>]
    member _.``Host paths map absolute logical paths beneath the test root``() =
        // Arrange
        let root = Path.Combine(Path.GetTempPath(), "keroosha-native-path-" + Guid.NewGuid().ToString("N"))
        Directory.CreateDirectory(root) |> ignore
        let environment = { HostEnvironment.system with Root = root }

        try
            // Act
            let actual = HostEnvironment.path environment "/etc/example.conf"

            // Assert
            Assert.That(actual, Is.EqualTo(Path.Combine(root, "etc", "example.conf")))
        finally
            Directory.Delete(root, true)

    [<Test>]
    member _.``System command runner forwards stdin and captures stdout``() =
        // Arrange
        let input = "helper input\n"

        // Act
        let result = HostEnvironment.system.Run "/bin/cat" [] (Some input)

        // Assert
        Assert.That(result.ExitCode, Is.EqualTo(0))
        Assert.That(result.Stdout, Is.EqualTo(input))
        Assert.That(result.Stderr, Is.Empty)

    [<Test>]
    member _.``System command runner captures stderr and nonzero exit codes``() =
        // Arrange
        let arguments = [ "-c"; "printf diagnostic >&2; exit 7" ]

        // Act
        let result = HostEnvironment.system.Run "/bin/sh" arguments None

        // Assert
        Assert.That(result.ExitCode, Is.EqualTo(7))
        Assert.That(result.Stdout, Is.Empty)
        Assert.That(result.Stderr, Is.EqualTo("diagnostic"))

    [<Test>]
    member _.``Atomic writes replace regular files with the requested mode``() =
        // Arrange
        let root = Path.Combine(Path.GetTempPath(), "keroosha-native-write-" + Guid.NewGuid().ToString("N"))
        Directory.CreateDirectory(root) |> ignore
        let target = Path.Combine(root, "state.json")
        File.WriteAllText(target, "old state")
        let expected = Encoding.UTF8.GetBytes("{\"version\":1}")
        let mode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite

        try
            // Act
            HostFiles.atomicWrite target expected mode

            // Assert
            Assert.That(File.ReadAllBytes(target), Is.EqualTo(expected :> obj))
            Assert.That(File.GetUnixFileMode(target), Is.EqualTo(mode))
        finally
            Directory.Delete(root, true)

    [<Test>]
    member _.``Atomic stream writes preserve the old binary when the source fails``() =
        // Arrange
        use temporary = new TemporaryDirectory("keroosha-native-stream-write-")
        let target = Path.Combine(temporary.Path, "traefik")
        File.WriteAllText(target, "old binary")
        let mode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
        use source = new FailingReadStream()
        let failure = TestDelegate(fun () -> HostFiles.atomicWriteStream target source mode)

        // Act and Assert
        Assert.Throws<IOException>(failure) |> ignore
        Assert.That(File.ReadAllText(target), Is.EqualTo("old binary"))
        Assert.That(Directory.GetFiles(temporary.Path), Is.EquivalentTo([| target |]))

    [<Test>]
    member _.``Atomic writes refuse symbolic links without changing their targets``() =
        // Arrange
        let root = Path.Combine(Path.GetTempPath(), "keroosha-native-symlink-" + Guid.NewGuid().ToString("N"))
        Directory.CreateDirectory(root) |> ignore
        let target = Path.Combine(root, "owned.json")
        let link = Path.Combine(root, "owned-link.json")
        let mode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite
        File.WriteAllText(target, "protected")
        File.CreateSymbolicLink(link, target) |> ignore

        try
            // Act
            let writeSymbolicLink () =
                HostFiles.atomicWrite link (Encoding.UTF8.GetBytes("replacement")) mode

            // Assert
            Assert.Throws<IOException>(fun () -> writeSymbolicLink ()) |> ignore
            Assert.That(File.ReadAllText(target), Is.EqualTo("protected"))
            Assert.That(FileInfo(link).LinkTarget, Is.EqualTo(target))
        finally
            Directory.Delete(root, true)

    [<Test>]
    member _.``Flock-compatible lock can be reacquired after disposal``() =
        // Arrange
        let root = Path.Combine(Path.GetTempPath(), "keroosha-native-lock-" + Guid.NewGuid().ToString("N"))
        Directory.CreateDirectory(root) |> ignore
        let lockPath = Path.Combine(root, "transaction.lock")

        try
            // Act
            let first = HostFiles.lockFile lockPath
            first.Dispose()
            let second = HostFiles.lockFile lockPath
            second.Dispose()

            // Assert
            Assert.That(File.Exists(lockPath), Is.True)
        finally
            Directory.Delete(root, true)
