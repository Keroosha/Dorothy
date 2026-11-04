namespace Dorothy.Tests

open System
open System.Diagnostics
open System.IO
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open Dorothy.HostHelper
open NUnit.Framework

[<RequireQualifiedAccess>]
module private SudoTestNative =
    let success (stdout: string) : CommandResult = { ExitCode = 0; Stdout = stdout; Stderr = "" }
    let failure (message: string) : CommandResult = { ExitCode = 1; Stdout = ""; Stderr = message }
    let notFound (message: string) : CommandResult = { ExitCode = 2; Stdout = ""; Stderr = message }

    let runExecutable (executable: string) (arguments: string list) : CommandResult =
        let startInfo = ProcessStartInfo()
        startInfo.FileName <- executable
        startInfo.UseShellExecute <- false
        startInfo.RedirectStandardOutput <- true
        startInfo.RedirectStandardError <- true
        startInfo.Environment["LC_ALL"] <- "C"
        for argument in arguments do startInfo.ArgumentList.Add argument
        use child = new Process()
        child.StartInfo <- startInfo
        if not (child.Start()) then invalidOp "Unable to start a sudo behavior-test command."
        let stdoutTask = child.StandardOutput.ReadToEndAsync()
        let stderrTask = child.StandardError.ReadToEndAsync()
        child.WaitForExit()
        { ExitCode = child.ExitCode
          Stdout = stdoutTask.GetAwaiter().GetResult()
          Stderr = stderrTask.GetAwaiter().GetResult() }

[<Sealed>]
type private SudoFakeHost(root: string) =
    let mutable failNextTransport = false
    let mutable failNextPolicyQuery = false
    let mutable hasEmptyGroup = true

    let mappedPath (logicalPath: string) =
        Path.Combine(root, logicalPath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar))

    let policyDirectory = mappedPath "/etc/sudoers.d"

    let currentAuthentication () =
        Directory.EnumerateFiles(policyDirectory, "90-keroosha-iac-*")
        |> Seq.tryPick (fun path ->
            let contents = File.ReadAllText path
            if contents.Contains("NOPASSWD:", StringComparison.Ordinal) then Some "!authenticate"
            elif contents.Contains("PASSWD:", StringComparison.Ordinal) then Some "authenticate"
            else None)
        |> Option.defaultValue "authenticate"

    let run (executable: string) (arguments: string list) (standardInput: string option) : CommandResult =
        match executable with
        | "getent" when arguments = [ "group"; "dorothy-empty-test" ] ->
            if hasEmptyGroup then SudoTestNative.success ("dorothy-empty-test:x:424242:" + Environment.NewLine)
            else SudoTestNative.notFound "unknown group"
        | "visudo"
        | "getent" -> SudoTestNative.runExecutable executable arguments
        | "sudo" when arguments = [ "-V" ] ->
            SudoTestNative.success "Sudo version 1.9.test\nSudoers path: /etc/sudoers\n"
        | "sudo" when List.contains "-ll" arguments ->
            let commandLine =
                match arguments |> List.tryFindIndex ((=) "--") with
                | Some index -> arguments |> List.skip (index + 1) |> String.concat " "
                | None -> ""
            if failNextPolicyQuery && List.contains "--" arguments then
                failNextPolicyQuery <- false
                SudoTestNative.failure "simulated effective-policy denial"
            else
                let policyEntry =
                    Directory.EnumerateFiles(policyDirectory, "90-keroosha-iac-*")
                    |> Seq.tryHead
                    |> Option.defaultValue "/etc/sudoers.d/90-keroosha-iac-test"
                let matched =
                    if commandLine = "" then ""
                    else "    Matched: " + commandLine + "\n"
                let output =
                    "User may run the following commands:\n"
                    + "Sudoers entry: /etc/sudoers\n"
                    + "    RunAsUsers: ALL\n"
                    + "    RunAsGroups: ALL\n"
                    + "    Commands:\n        ALL\n"
                    + "Sudoers entry: " + policyEntry + "\n"
                    + "    RunAsUsers: ALL\n"
                    + "    RunAsGroups: ALL\n"
                    + "    Options: !setenv, " + currentAuthentication () + "\n"
                    + "    Commands:\n        ALL\n"
                    + matched
                SudoTestNative.success output
        | "/usr/sbin/runuser" when List.contains "--version" arguments ->
            SudoTestNative.success "keroosha-iac-helper protocol 1\n"
        | "/usr/sbin/runuser" when standardInput.IsSome ->
            SudoTestNative.success "{\"exists\":false,\"inSync\":false,\"actual\":{}}\n"
        | "/usr/sbin/runuser" ->
            if failNextTransport then
                failNextTransport <- false
                SudoTestNative.failure "simulated fresh transport denial"
            else SudoTestNative.success "0\n"
        | _ -> SudoTestNative.failure "unexpected command"

    do
        for directory in
            [ "/etc"
              "/etc/sudoers.d"
              "/var"
              "/var/lib"
              "/var/lib/keroosha-iac" ] do
            let path = mappedPath directory
            Directory.CreateDirectory(path) |> ignore
            File.SetUnixFileMode(path, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)
        let included = mappedPath "/etc/sudoers.d"
        let sudoers = mappedPath "/etc/sudoers"
        File.WriteAllText(sudoers, "Defaults env_reset\n@includedir " + included + "\n")
        File.SetUnixFileMode(sudoers, UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
    member _.RemoveEmptyGroup() = hasEmptyGroup <- false

    member _.Environment = TestSupport.fakeHostEnvironment root run (fun () -> DateTimeOffset.UnixEpoch)
    member _.MapPath(logicalPath: string) = mappedPath logicalPath
    member _.FailNextPolicyQuery() = failNextPolicyQuery <- true
    member _.FailNextTransport() = failNextTransport <- true
    member _.AddUnrelatedPolicy(name: string, contents: string) =
        let path = Path.Combine(policyDirectory, name)
        File.WriteAllText(path, contents)
        File.SetUnixFileMode(path, UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
        path

[<RequireQualifiedAccess>]
module private SudoTestHelpers =
    let resourceId = "urn:pulumi:test::project::dorothy:host:Sudo::main"

    let ownerDigest =
        SHA256.HashData(Encoding.UTF8.GetBytes resourceId)
        |> Convert.ToHexString
        |> fun value -> value.ToLowerInvariant()

    let runAsJson (operation: string) (host: SudoFakeHost) (grants: JsonArray) : JsonNode =
        let request = JsonObject()
        request["operation"] <- JsonValue.Create(operation)
        request["resourceId"] <- JsonValue.Create(resourceId)
        request["connectionUser"] <- JsonValue.Create(Environment.UserName)
        request["grants"] <- grants
        use document = JsonDocument.Parse(request.ToJsonString())
        Sudo.handle host.Environment document.RootElement

    let subject (kind: string) (name: string) : JsonObject =
        let node = JsonObject()
        node["kind"] <- JsonValue.Create(kind)
        node["name"] <- JsonValue.Create(name)
        node

    let runAsAll () : JsonObject =
        let node = JsonObject()
        node["kind"] <- JsonValue.Create("all")
        node

    let runAsSpecific (user: string) : JsonObject =
        let node = JsonObject()
        node["kind"] <- JsonValue.Create("specific")
        node["user"] <- JsonValue.Create(user)
        node

    let command (path: string) (kind: string) (value: string option) : JsonObject =
        let node = JsonObject()
        node["path"] <- JsonValue.Create(path)
        let arguments = JsonObject()
        arguments["kind"] <- JsonValue.Create(kind)
        value |> Option.iter (fun text -> arguments["value"] <- JsonValue.Create(text))
        node["arguments"] <- arguments
        node

    let grant
        (name: string)
        (subjects: JsonObject list)
        (runAs: JsonObject)
        (authentication: string option)
        (allCommands: bool)
        (commands: JsonObject list)
        : JsonObject =
        let node = JsonObject()
        node["name"] <- JsonValue.Create(name)
        let subjectArray = JsonArray()
        for value in subjects do subjectArray.Add value
        node["subjects"] <- subjectArray
        node["runAs"] <- runAs
        authentication |> Option.iter (fun value -> node["authentication"] <- JsonValue.Create(value))
        node["allCommands"] <- JsonValue.Create(allCommands)
        let commandArray = JsonArray()
        for value in commands do commandArray.Add value
        node["commands"] <- commandArray
        node

    let grants (nodes: JsonObject list) =
        let result = JsonArray()
        for node in nodes do result.Add(JsonNode.Parse(node.ToJsonString()))
        result

    let getBool (node: JsonNode) (name: string) = node[name].GetValue<bool>()
    let getGrantField (node: JsonNode) (field: string) =
        let actual = node.["actual"]
        let grants = actual.["grants"]
        let grant = grants.[0]
        grant.[field]
    let getGrantCoverage (node: JsonNode) =
        let value = getGrantField node "coverage"
        value.GetValue<string>()
    let getGrantEffectiveVerified (node: JsonNode) =
        let value = getGrantField node "effectiveVerified"
        value.GetValue<bool>()
    let sudoersPath (host: SudoFakeHost) =
        host.MapPath("/etc/sudoers.d/90-keroosha-iac-" + ownerDigest)

    let statePath (host: SudoFakeHost) =
        host.MapPath("/var/lib/keroosha-iac/sudoers/" + ownerDigest + ".json")


[<TestFixture>]
type SudoTests() =
    let makeHost () =
        let temporary = new TemporaryDirectory("dorothy-sudo-")
        let pathValue = Environment.GetEnvironmentVariable("PATH")
        let visudoOnPath =
            (if isNull pathValue then [||] else pathValue.Split(Path.PathSeparator))
            |> Array.exists (fun directory -> File.Exists(Path.Combine(directory, "visudo")))
        if not (File.Exists("/usr/sbin/visudo") || visudoOnPath) then
            (temporary :> IDisposable).Dispose()
            Assert.Ignore("Sudo behavior regressions require the native visudo executable.")
        temporary, SudoFakeHost(temporary.Path)

    [<Test>]
    member _.``Installs a passwordless all-command grant for all run-as identities``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let rule =
            SudoTestHelpers.grant
                "operator-admin"
                [ SudoTestHelpers.subject "user" Environment.UserName
                  SudoTestHelpers.subject "group" "root" ]
                (SudoTestHelpers.runAsAll ())
                (Some "passwordless")
                true
                []

        let applied = SudoTestHelpers.runAsJson "apply" host (SudoTestHelpers.grants [ rule ])

        Assert.That(SudoTestHelpers.getBool applied "exists", Is.True)
        Assert.That(SudoTestHelpers.getBool applied "inSync", Is.True)
        Assert.That(File.Exists(SudoTestHelpers.sudoersPath host), Is.True)
        Assert.That(File.GetUnixFileMode(SudoTestHelpers.sudoersPath host), Is.EqualTo(UnixFileMode.UserRead ||| UnixFileMode.GroupRead))
        Assert.That(File.Exists(SudoTestHelpers.statePath host), Is.True)
        Assert.That(File.GetUnixFileMode(SudoTestHelpers.statePath host), Is.EqualTo(UnixFileMode.UserRead ||| UnixFileMode.UserWrite))

        let read = SudoTestHelpers.runAsJson "read" host (SudoTestHelpers.grants [ rule ])
        Assert.That(SudoTestHelpers.getBool read "inSync", Is.True)
    [<Test>]
    member _.``Rejects an owned passwordless ALL rule overridden by a required exact rule``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let subject = SudoTestHelpers.subject "user" Environment.UserName
        let broad =
            SudoTestHelpers.grant
                "operator-admin"
                [ subject ]
                (SudoTestHelpers.runAsAll ())
                (Some "passwordless")
                true
                []
        let exact =
            SudoTestHelpers.grant
                "operator-apt"
                [ SudoTestHelpers.subject "user" Environment.UserName ]
                (SudoTestHelpers.runAsSpecific "root")
                (Some "required")
                false
                [ SudoTestHelpers.command "/usr/bin/apt" "exact" (Some "update") ]
        let apply () = SudoTestHelpers.runAsJson "apply" host (SudoTestHelpers.grants [ broad; exact ]) |> ignore

        Assert.Throws<Sudo.BackendError>(TestDelegate apply) |> ignore
        Assert.That(File.Exists(SudoTestHelpers.sudoersPath host), Is.False)
        Assert.That(File.Exists(SudoTestHelpers.statePath host), Is.False)



    [<Test>]
    member _.``Rejects sudoers and command injection syntax before creating ownership``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let unsafe =
            SudoTestHelpers.grant
                "unsafe"
                [ SudoTestHelpers.subject "user" Environment.UserName ]
                (SudoTestHelpers.runAsSpecific "root")
                None
                false
                [ SudoTestHelpers.command "/usr/bin/apt" "exact" (Some "update\nALL=(ALL) NOPASSWD: ALL") ]
        let apply () = SudoTestHelpers.runAsJson "apply" host (SudoTestHelpers.grants [ unsafe ]) |> ignore

        Assert.Throws<Sudo.BackendError>(TestDelegate apply) |> ignore
        Assert.That(File.Exists(SudoTestHelpers.sudoersPath host), Is.False)
        Assert.That(File.Exists(SudoTestHelpers.statePath host), Is.False)

    [<Test>]
    member _.``Rejects a foreign deterministic sudoers file without replacing it``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let foreign = "# independently managed\n"
        File.WriteAllText(SudoTestHelpers.sudoersPath host, foreign)
        File.SetUnixFileMode(SudoTestHelpers.sudoersPath host, UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
        let rule =
            SudoTestHelpers.grant
                "operator-admin"
                [ SudoTestHelpers.subject "user" Environment.UserName ]
                (SudoTestHelpers.runAsAll ())
                (Some "passwordless")
                true
                []
        let apply () = SudoTestHelpers.runAsJson "apply" host (SudoTestHelpers.grants [ rule ]) |> ignore

        Assert.Throws<Sudo.BackendError>(TestDelegate apply) |> ignore
        Assert.That(File.ReadAllText(SudoTestHelpers.sudoersPath host), Is.EqualTo(foreign))
        Assert.That(File.Exists(SudoTestHelpers.statePath host), Is.False)

    [<Test>]
    member _.``A failed effective candidate check restores the previous owned policy``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let originalRule =
            SudoTestHelpers.grant
                "operator-admin"
                [ SudoTestHelpers.subject "user" Environment.UserName ]
                (SudoTestHelpers.runAsAll ())
                (Some "passwordless")
                true
                []
        SudoTestHelpers.runAsJson "apply" host (SudoTestHelpers.grants [ originalRule ]) |> ignore
        let target = SudoTestHelpers.sudoersPath host
        let previous = File.ReadAllBytes target
        let replacementRule =
            SudoTestHelpers.grant
                "operator-maintenance"
                [ SudoTestHelpers.subject "user" Environment.UserName ]
                (SudoTestHelpers.runAsSpecific "root")
                (Some "passwordless")
                false
                [ SudoTestHelpers.command "/usr/bin/apt" "exact" (Some "update") ]
        host.FailNextPolicyQuery()
        let update () = SudoTestHelpers.runAsJson "apply" host (SudoTestHelpers.grants [ replacementRule ]) |> ignore

        Assert.Throws<Sudo.BackendError>(TestDelegate update) |> ignore
        Assert.That(File.ReadAllBytes(target) = previous, Is.True)
        Assert.That(File.Exists(host.MapPath("/var/lib/keroosha-iac/sudoers/" + SudoTestHelpers.ownerDigest + ".pending.json")), Is.False)
        let read = SudoTestHelpers.runAsJson "read" host (SudoTestHelpers.grants [ originalRule ])
        Assert.That(SudoTestHelpers.getBool read "inSync", Is.True)

    [<Test>]
    member _.``Fresh transport protection rolls back a candidate that removes management access``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let rule =
            SudoTestHelpers.grant
                "operator-admin"
                [ SudoTestHelpers.subject "user" Environment.UserName ]
                (SudoTestHelpers.runAsAll ())
                (Some "passwordless")
                true
                []
        host.FailNextTransport()
        let apply () = SudoTestHelpers.runAsJson "apply" host (SudoTestHelpers.grants [ rule ]) |> ignore

        Assert.Throws<Sudo.BackendError>(TestDelegate apply) |> ignore
        Assert.That(File.Exists(SudoTestHelpers.sudoersPath host), Is.False)
        Assert.That(File.Exists(SudoTestHelpers.statePath host), Is.False)

    [<Test>]
    member _.``Read reports permission drift without repairing it and delete preserves foreign policy``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let unrelatedContents = "# unrelated administrator policy\n"
        let unrelated = host.AddUnrelatedPolicy("20-local-policy", unrelatedContents)
        let rule =
            SudoTestHelpers.grant
                "operator-admin"
                [ SudoTestHelpers.subject "user" Environment.UserName ]
                (SudoTestHelpers.runAsAll ())
                (Some "passwordless")
                true
                []
        SudoTestHelpers.runAsJson "apply" host (SudoTestHelpers.grants [ rule ]) |> ignore
        let target = SudoTestHelpers.sudoersPath host
        File.SetUnixFileMode(target, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.GroupRead)

        let drift = SudoTestHelpers.runAsJson "read" host (SudoTestHelpers.grants [ rule ])
        Assert.That(SudoTestHelpers.getBool drift "inSync", Is.False)
        Assert.That(File.GetUnixFileMode(target), Is.EqualTo(UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.GroupRead))

        SudoTestHelpers.runAsJson "apply" host (SudoTestHelpers.grants [ rule ]) |> ignore
        SudoTestHelpers.runAsJson "delete" host (SudoTestHelpers.grants [ rule ]) |> ignore
        Assert.That(File.Exists(target), Is.False)
        Assert.That(File.ReadAllText(unrelated), Is.EqualTo(unrelatedContents))
    [<Test>]
    member _.``An empty existing group grant is structurally managed and remains deletable``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let rule =
            SudoTestHelpers.grant
                "empty-operators"
                [ SudoTestHelpers.subject "group" "dorothy-empty-test" ]
                (SudoTestHelpers.runAsAll ())
                (Some "passwordless")
                false
                [ SudoTestHelpers.command "/usr/bin/printf" "exact" (Some "^literal$") ]

        let applied = SudoTestHelpers.runAsJson "apply" host (SudoTestHelpers.grants [ rule ])
        Assert.That(SudoTestHelpers.getBool applied "inSync", Is.True)
        Assert.That(SudoTestHelpers.getGrantCoverage applied, Is.EqualTo("empty-group-structural"))
        Assert.That(SudoTestHelpers.getGrantEffectiveVerified applied, Is.False)

        host.RemoveEmptyGroup()
        let drift = SudoTestHelpers.runAsJson "read" host (SudoTestHelpers.grants [ rule ])
        Assert.That(SudoTestHelpers.getBool drift "inSync", Is.False)
        Assert.That(SudoTestHelpers.getGrantCoverage drift, Is.EqualTo("unresolved-principal"))
        Assert.That(SudoTestHelpers.getGrantEffectiveVerified drift, Is.False)
        let deleted = SudoTestHelpers.runAsJson "delete" host (SudoTestHelpers.grants [ rule ])
        Assert.That(SudoTestHelpers.getBool deleted "exists", Is.False)
        Assert.That(File.Exists(SudoTestHelpers.sudoersPath host), Is.False)
