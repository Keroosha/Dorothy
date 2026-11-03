namespace Dorothy.Tests

open System
open System.IO
open System.Text
open Dorothy.HostHelper
open NUnit.Framework

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
