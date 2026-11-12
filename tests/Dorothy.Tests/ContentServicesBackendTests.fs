namespace Dorothy.Tests

open System
open System.IO
open System.IO.Compression
open System.Formats.Tar
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open System.Net
open System.Net.Sockets
open System.Threading.Tasks
open Dorothy.HostHelper
open NUnit.Framework

[<TestFixture>]
type ContentServicesBackendTests() =
    let digest (bytes: byte array) = SHA256.HashData bytes |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()
    let environment root = { HostEnvironment.system with Root = root }
    let invoke root (request: JsonObject) =
        use document = JsonDocument.Parse(request.ToJsonString())
        Content.handle (environment root) document.RootElement
    let request (operation: string) (kind: string) (ownership: string) (destination: string) (bytes: byte array) =
        let node = JsonObject()
        node["operation"] <- JsonValue.Create operation
        node["kind"] <- JsonValue.Create kind
        node["ownership"] <- JsonValue.Create ownership
        node["sha256"] <- JsonValue.Create(digest bytes)
        node["data"] <- JsonValue.Create(Convert.ToBase64String bytes)
        let target = JsonObject()
        target["path"] <- JsonValue.Create destination
        target["mode"] <- JsonValue.Create(if kind = "directory" then 0o700 else 0o600)
        let targets = JsonArray()
        targets.Add target
        node["targets"] <- targets
        node
    let bytes value = Encoding.UTF8.GetBytes(value: string)
    let boolean (node: JsonNode) (name: string) = node[name].GetValue<bool>()

    [<Test>]
    member _.``Managed content repairs bytes and permissions and deletes its target``() =
        use root = new TemporaryDirectory("dorothy-content-")
        let desired = request "apply" "text" "managed" "/etc/config" (bytes "first")
        let created = invoke root.Path desired
        let path = Path.Combine(root.Path, "etc/config")
        Assert.That(File.ReadAllText path, Is.EqualTo "first")
        Assert.That(boolean created "inSync", Is.True)
        File.WriteAllText(path, "runtime")
        File.SetUnixFileMode(path, enum<UnixFileMode> 0o644)
        desired["operation"] <- JsonValue.Create "read"
        let drift = invoke root.Path desired
        Assert.That(boolean drift "inSync", Is.False)
        Assert.That(File.ReadAllText path, Is.EqualTo "runtime")
        desired["operation"] <- JsonValue.Create "apply"
        invoke root.Path desired |> ignore
        Assert.That(File.ReadAllText path, Is.EqualTo "first")
        Assert.That(int (File.GetUnixFileMode path), Is.EqualTo 0o600)
        desired["operation"] <- JsonValue.Create "delete"
        invoke root.Path desired |> ignore
        Assert.That(File.Exists path, Is.False)

    [<Test>]
    member _.``CreateOnly retains runtime bytes and mode across update refresh and delete``() =
        use root = new TemporaryDirectory("dorothy-seed-")
        let desired = request "apply" "text" "createOnly" "/etc/wg.conf" (bytes "seed")
        invoke root.Path desired |> ignore
        let path = Path.Combine(root.Path, "etc/wg.conf")
        File.WriteAllText(path, "runtime peers")
        File.SetUnixFileMode(path, enum<UnixFileMode> 0o640)
        let updated = request "apply" "text" "createOnly" "/etc/wg.conf" (bytes "new seed")
        // Existing CreateOnly targets do not even decode the new source bytes.
        updated["data"] <- JsonValue.Create "not base64"
        invoke root.Path updated |> ignore
        updated["operation"] <- JsonValue.Create "read"
        Assert.That(boolean (invoke root.Path updated) "inSync", Is.True)
        updated["operation"] <- JsonValue.Create "delete"
        invoke root.Path updated |> ignore
        Assert.That(File.ReadAllText path, Is.EqualTo "runtime peers")
        Assert.That(int (File.GetUnixFileMode path), Is.EqualTo 0o640)
        File.Delete path
        updated["operation"] <- JsonValue.Create "read"
        Assert.That(boolean (invoke root.Path updated) "inSync", Is.False)

    [<Test>]
    member _.``Digest mismatch leaves previous target untouched and no staging files``() =
        use root = new TemporaryDirectory("dorothy-digest-")
        let desired = request "apply" "file" "managed" "/bin/tool" (bytes "old")
        invoke root.Path desired |> ignore
        desired["data"] <- JsonValue.Create(Convert.ToBase64String(bytes "unverified"))
        Assert.Throws<Content.BackendError>(fun () -> invoke root.Path desired |> ignore) |> ignore
        Assert.That(File.ReadAllText(Path.Combine(root.Path, "bin/tool")), Is.EqualTo "old")
        Assert.That(Directory.GetFiles(Path.Combine(root.Path, "bin")), Has.Length.EqualTo 1)

    [<Test>]
    member _.``Atomic staging keeps previous bytes until publish and sets final permissions before rename``() =
        use root = new TemporaryDirectory("dorothy-atomic-")
        let target: Content.Target = { Path = "/target"; Source = ""; Mode = 0o640; Owner = None; Group = None }
        let path = Path.Combine(root.Path, "target")
        File.WriteAllText(path, "old")
        use input = new MemoryStream(bytes "new")
        let staged, destination = Content.stageFile (environment root.Path) target input
        Assert.That(Path.GetDirectoryName staged, Is.EqualTo(Path.GetDirectoryName path))
        Assert.That(File.ReadAllText path, Is.EqualTo "old")
        Assert.That(File.ReadAllText staged, Is.EqualTo "new")
        Assert.That(int (File.GetUnixFileMode staged), Is.EqualTo 0o640)
        File.Move(staged, destination, true)
        Assert.That(File.ReadAllText path, Is.EqualTo "new")

    [<TestCase("zip")>]
    [<TestCase("tarGz")>]
    [<TestCase("tarZst")>]
    member _.``Selective archive extraction uses verified cache and detects later drift``(format: string) =
        use root = new TemporaryDirectory("dorothy-archive-")
        let archivePath = Path.Combine(root.Path, "archive")
        if format = "zip" then
            use archive = ZipFile.Open(archivePath, ZipArchiveMode.Create)
            for name, contents in [ "bin/tool", "binary"; "ignored", "ignore me" ] do
                use output = archive.CreateEntry(name).Open()
                output.Write(bytes contents)
        else
            use file = File.Create archivePath
            use input: Stream = if format = "tarGz" then new GZipStream(file, CompressionMode.Compress) else file
            use archive = new TarWriter(input)
            for name, contents in [ "bin/tool", "binary"; "ignored", "ignore me" ] do
                use stream = new MemoryStream(bytes contents)
                let entry = PaxTarEntry(TarEntryType.RegularFile, name)
                entry.DataStream <- stream
                archive.WriteEntry entry
        if format = "tarZst" then
            let compressed = archivePath + ".zst"
            let result = HostEnvironment.system.Run "/usr/bin/zstd" [ "-q"; "-o"; compressed; "--"; archivePath ] None
            Assert.That(result.ExitCode, Is.Zero, result.Stderr)
            File.Move(compressed, archivePath, true)
        let archiveBytes = File.ReadAllBytes archivePath
        let cacheDirectory = Path.Combine(root.Path, "var/cache/keroosha-iac/content")
        Directory.CreateDirectory cacheDirectory |> ignore
        File.Copy(archivePath, Path.Combine(cacheDirectory, digest archiveBytes))
        let desired = request "apply" "archive" "managed" "/usr/bin/tool" archiveBytes
        desired["format"] <- JsonValue.Create format
        desired["url"] <- JsonValue.Create "http://127.0.0.1:1/never-used"
        desired["targets"].[0].["source"] <- JsonValue.Create "bin/tool"
        let created = invoke root.Path desired
        Assert.That(File.ReadAllText(Path.Combine(root.Path, "usr/bin/tool")), Is.EqualTo "binary")
        Assert.That(File.Exists(Path.Combine(root.Path, "ignored")), Is.False)
        Assert.That(boolean created "inSync", Is.True)
        desired["hashes"] <- created["hashes"].DeepClone()
        desired["operation"] <- JsonValue.Create "read"
        Assert.That(boolean (invoke root.Path desired) "inSync", Is.True)
        File.WriteAllText(Path.Combine(root.Path, "usr/bin/tool"), "drift")
        Assert.That(boolean (invoke root.Path desired) "inSync", Is.False)

    [<Test>]
    member _.``Missing selected member never publishes other selected members``() =
        use root = new TemporaryDirectory("dorothy-missing-member-")
        let archivePath = Path.Combine(root.Path, "archive")
        do
            use archive = ZipFile.Open(archivePath, ZipArchiveMode.Create)
            use output = archive.CreateEntry("present").Open()
            output.Write(bytes "new")
        let archiveBytes = File.ReadAllBytes archivePath
        let cacheDirectory = Path.Combine(root.Path, "var/cache/keroosha-iac/content")
        Directory.CreateDirectory cacheDirectory |> ignore
        File.Copy(archivePath, Path.Combine(cacheDirectory, digest archiveBytes))
        File.WriteAllText(Path.Combine(root.Path, "first"), "old")
        let desired = request "apply" "archive" "managed" "/first" archiveBytes
        desired["format"] <- JsonValue.Create "zip"
        desired["targets"].[0].["source"] <- JsonValue.Create "present"
        let second = desired["targets"].[0].DeepClone()
        second["path"] <- JsonValue.Create "/second"
        second["source"] <- JsonValue.Create "absent"
        desired["targets"].AsArray().Add second
        Assert.Throws<Content.BackendError>(fun () -> invoke root.Path desired |> ignore) |> ignore
        Assert.That(File.ReadAllText(Path.Combine(root.Path, "first")), Is.EqualTo "old")
        Assert.That(File.Exists(Path.Combine(root.Path, "second")), Is.False)

    [<Test>]
    member _.``Directory ignores runtime children and retains nonempty directory on deletion``() =
        use root = new TemporaryDirectory("dorothy-directory-")
        let desired = request "apply" "directory" "managed" "/peers" [||]
        invoke root.Path desired |> ignore
        File.WriteAllText(Path.Combine(root.Path, "peers/peer"), "runtime")
        desired["operation"] <- JsonValue.Create "read"
        Assert.That(boolean (invoke root.Path desired) "inSync", Is.True)
        desired["operation"] <- JsonValue.Create "delete"
        invoke root.Path desired |> ignore
        Assert.That(File.ReadAllText(Path.Combine(root.Path, "peers/peer")), Is.EqualTo "runtime")
        File.Delete(Path.Combine(root.Path, "peers/peer"))
        invoke root.Path desired |> ignore
        Assert.That(Directory.Exists(Path.Combine(root.Path, "peers")), Is.False)

    [<Test>]
    member _.``Symlink destinations and traversal archive selectors are rejected``() =
        use root = new TemporaryDirectory("dorothy-links-")
        File.WriteAllText(Path.Combine(root.Path, "foreign"), "untouched")
        File.CreateSymbolicLink(Path.Combine(root.Path, "target"), "foreign") |> ignore
        let desired = request "apply" "text" "managed" "/target" (bytes "new")
        Assert.Throws<Content.BackendError>(fun () -> invoke root.Path desired |> ignore) |> ignore
        Assert.That(File.ReadAllText(Path.Combine(root.Path, "foreign")), Is.EqualTo "untouched")
        let archive = request "apply" "archive" "managed" "/other" (bytes "unused")
        archive["targets"].[0].["source"] <- JsonValue.Create "../escape"
        Assert.Throws<Content.BackendError>(fun () -> invoke root.Path archive |> ignore) |> ignore

    [<TestCase(true)>]
    [<TestCase(false)>]
    member _.``Systemd lifecycle distinguishes owned and package units``(managed: bool) =
        use root = new TemporaryDirectory("dorothy-systemd-")
        let calls = ResizeArray<string list>()
        let mutable active = false
        let mutable enabled = false
        let run _ arguments (stdin: string option) =
            Assert.That(stdin.IsNone, Is.True)
            calls.Add arguments
            match arguments.Head with
            | "enable" -> enabled <- true
            | "disable" -> enabled <- false
            | "start" | "restart" -> active <- true
            | "stop" -> active <- false
            | _ -> ()
            { ExitCode = 0; Stderr = ""
              Stdout = "LoadState=loaded\nActiveState=" + (if active then "active" else "inactive") + "\nUnitFileState=" + (if enabled then "enabled" else "disabled") + "\n" }
        let env = TestSupport.fakeHostEnvironment root.Path run (fun () -> DateTimeOffset.UnixEpoch)
        let desired = JsonObject()
        desired["operation"] <- JsonValue.Create "apply"
        desired["name"] <- JsonValue.Create "example"
        desired["managed"] <- JsonValue.Create managed
        desired["configuration"] <- JsonValue.Create(if managed then "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n" else "")
        desired["restart"] <- JsonValue.Create false
        let invoke () =
            use doc = JsonDocument.Parse(desired.ToJsonString())
            Services.handle env doc.RootElement
        Assert.That(boolean (invoke ()) "inSync", Is.True)
        Assert.That(File.Exists(Path.Combine(root.Path, "etc/systemd/system/example.service")), Is.EqualTo managed)
        Assert.That(calls |> Seq.exists (fun args -> args.Head = "daemon-reload"), Is.EqualTo managed)
        calls.Clear()
        invoke () |> ignore
        Assert.That(calls |> Seq.exists (fun args -> args.Head = "restart"), Is.False)
        desired["restart"] <- JsonValue.Create true
        invoke () |> ignore
        Assert.That(calls |> Seq.exists (fun args -> args.Head = "restart"), Is.True)
        if managed then
            calls.Clear()
            let unitPath = Path.Combine(root.Path, "etc/systemd/system/example.service")
            File.SetUnixFileMode(unitPath, enum<UnixFileMode> 0o600)
            desired["restart"] <- JsonValue.Create false
            Assert.That(boolean (invoke ()) "inSync", Is.True)
            Assert.That(int (File.GetUnixFileMode unitPath), Is.EqualTo 0o644)
            Assert.That(calls |> Seq.exists (fun args -> args.Head = "daemon-reload"), Is.True)
            Assert.That(calls |> Seq.exists (fun args -> args.Head = "restart"), Is.True)
        calls.Clear()
        desired["operation"] <- JsonValue.Create "delete"
        invoke () |> ignore
        Assert.That(active, Is.False)
        Assert.That(enabled, Is.False)
        Assert.That(File.Exists(Path.Combine(root.Path, "etc/systemd/system/example.service")), Is.False)
        Assert.That(calls |> Seq.exists (fun args -> args.Head = "daemon-reload"), Is.EqualTo managed)

    [<TestCase(true)>]
    [<TestCase(false)>]
    member _.``Host download verifies digest before installation and cached bytes avoid subsequent network``(validDigest: bool) =
        use root = new TemporaryDirectory("dorothy-download-")
        use listener = new TcpListener(IPAddress.Loopback, 0)
        listener.Start()
        let port = (listener.LocalEndpoint :?> IPEndPoint).Port
        let body = bytes "downloaded binary"
        let observed = ResizeArray<string>()
        let response = Task.Run(Action(fun () ->
            use client = listener.AcceptTcpClient()
            use stream = client.GetStream()
            use reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true)
            let mutable line = reader.ReadLine()
            while not (String.IsNullOrEmpty line) do
                observed.Add line
                line <- reader.ReadLine()
            let header = bytes (sprintf "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" body.Length)
            stream.Write header
            stream.Write body
            stream.Flush()))
        let desired = request "apply" "download" "managed" "/tool" body
        desired["url"] <- JsonValue.Create(sprintf "http://127.0.0.1:%d/artifact" port)
        let headers = JsonObject()
        headers["Authorization"] <- JsonValue.Create "Bearer private-test-token"
        desired["headers"] <- headers
        let path = Path.Combine(root.Path, "tool")
        File.WriteAllText(path, "original")
        if not validDigest then desired["sha256"] <- JsonValue.Create(String.replicate 64 "a")
        try
            if validDigest then
                invoke root.Path desired |> ignore
                Assert.That(File.ReadAllBytes path, Is.EqualTo(box body))
            else
                Assert.Throws<Content.BackendError>(fun () -> invoke root.Path desired |> ignore) |> ignore
                Assert.That(File.ReadAllText path, Is.EqualTo "original")
            Assert.That(response.Wait(TimeSpan.FromSeconds 5.), Is.True)
            Assert.That(observed |> Seq.exists (fun line -> line = "Authorization: Bearer private-test-token"), Is.True)
        finally listener.Stop()
        if validDigest then
            desired["url"] <- JsonValue.Create "http://127.0.0.1:1/unreachable"
            headers["Authorization"] <- JsonValue.Create "rotated-token"
            File.WriteAllText(path, "drift")
            invoke root.Path desired |> ignore
            Assert.That(File.ReadAllBytes path, Is.EqualTo(box body))

    [<Test>]
    member _.``Requested owner and group are applied without privileges and checked for drift``() =
        use root = new TemporaryDirectory("dorothy-owner-")
        let owner = (HostEnvironment.system.Run "/usr/bin/id" [ "-un" ] None).Stdout.Trim()
        let group = (HostEnvironment.system.Run "/usr/bin/id" [ "-gn" ] None).Stdout.Trim()
        let desired = request "apply" "text" "managed" "/owned" (bytes "owned")
        desired["targets"].[0].["owner"] <- JsonValue.Create owner
        desired["targets"].[0].["group"] <- JsonValue.Create group
        Assert.That(boolean (invoke root.Path desired) "inSync", Is.True)
        desired["operation"] <- JsonValue.Create "read"
        desired["targets"].[0].["owner"] <- JsonValue.Create "nonexistent-owner"
        Assert.That(boolean (invoke root.Path desired) "inSync", Is.False)
