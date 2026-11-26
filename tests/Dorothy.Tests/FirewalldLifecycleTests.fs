namespace Dorothy.Tests

open System
open System.IO
open System.Text
open System.Text.Json.Nodes
open System.Text.Json
open Dorothy.DSL
open Dorothy.HostHelper
open NUnit.Framework

[<TestFixture; NonParallelizable>]
type FirewalldLifecycleTests() =

    let physical (root: string) (logical: string) =
        Path.Combine(root, logical.TrimStart('/').Replace('/', Path.DirectorySeparatorChar))

    let writeFile (root: string) (logical: string) (text: string) (mode: int) =
        let target = physical root logical
        Directory.CreateDirectory(Path.GetDirectoryName target) |> ignore
        HostFiles.atomicWrite target (Encoding.UTF8.GetBytes text) (enum<UnixFileMode> mode)

    let journal (owner: string) (baseline: string option) (managed: string option) =
        let value = JsonObject()
        value["version"] <- JsonValue.Create 1
        value["ownerId"] <- JsonValue.Create owner
        value["baseline"] <- match baseline with None -> null | Some text -> JsonValue.Create text :> JsonNode
        value["managed"] <- match managed with None -> null | Some text -> JsonValue.Create text :> JsonNode
        value["pending"] <- null
        value["baselineMode"] <- JsonValue.Create 0o644
        value["managedMode"] <- JsonValue.Create 0o644
        value

    let withHost (action: HostEnvironment -> string -> unit) =
        let root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-lifecycle-" + Guid.NewGuid().ToString("N"))
        for directory in [ "etc/firewalld/zones"; "etc/systemd/system"; "run/lock"; "var/lib" ] do
            Directory.CreateDirectory(Path.Combine(root, directory)) |> ignore
        let run (executable: string) (arguments: string list) (_input: string option) : CommandResult =
            if executable = "stat" then
                if List.contains "%u:%g" arguments then
                    { ExitCode = 0; Stdout = "0:0"; Stderr = "" }
                else
                    let target = List.last arguments
                    let mode = File.GetUnixFileMode target |> int |> fun value -> Convert.ToString(value, 8)
                    { ExitCode = 0; Stdout = "0:" + mode; Stderr = "" }
            elif executable = "/usr/bin/systemctl" then
                let createLink directory name target =
                    Directory.CreateDirectory(directory) |> ignore
                    let link = Path.Combine(directory, name)
                    if isNull (FileInfo(link).LinkTarget) && not (File.Exists link || Directory.Exists link) then
                        File.CreateSymbolicLink(link, target) |> ignore
                match arguments with
                | [ "enable"; "keroosha-iac-firewalld-boot-recovery.service" ] ->
                    createLink (Path.Combine(root, "etc/systemd/system/multi-user.target.wants")) "keroosha-iac-firewalld-boot-recovery.service" "../keroosha-iac-firewalld-boot-recovery.service"
                | [ "enable"; "--now"; "keroosha-iac-firewalld-rollback.timer" ] ->
                    let target = Path.Combine(root, "etc/systemd/system/keroosha-iac-firewalld-rollback.timer")
                    createLink (Path.Combine(root, "etc/systemd/system/timers.target.wants")) "keroosha-iac-firewalld-rollback.timer" target
                | _ -> ()
                { ExitCode = 0; Stdout = "success"; Stderr = "" }
            else
                invalidOp ("Unexpected lifecycle command: " + executable + " " + String.concat " " arguments)
        let environment: HostEnvironment =
            { Root = root
              Run = run
              UtcNow = fun () -> DateTimeOffset.UnixEpoch }
        try action environment root
        finally
            if Directory.Exists root then Directory.Delete(root, true)

    let configuration = FirewalldModel.empty "zone" "lifecycle"
    let logicalPath = "/etc/firewalld/zones/lifecycle.xml"
    let owner = "test-owner"
    let before = "<zone><service name=\"ssh\"/></zone>\n"
    let after = "<zone><service name=\"ssh\"/><port port=\"443\" protocol=\"tcp\"/></zone>\n"

    let transact
        (environment: HostEnvironment)
        (journal: JsonObject)
        (before: string option)
        (after: string option)
        (releaseOnRollback: bool)
        (deleteOnConfirm: bool)
        =
        let target = physical environment.Root logicalPath
        if deleteOnConfirm then journal["deleteOnConfirm"] <- JsonValue.Create true
        let write (contents: string option) (mode: int) =
            match contents with
            | Some text -> writeFile environment.Root logicalPath text mode
            | None ->
                if File.Exists target then
                    File.Delete target
                    HostFiles.syncDirectory (Path.GetDirectoryName target)
        let validate _ = ()
        let activate () = ()
        FirewalldLifecycle.transact
            environment configuration journal releaseOnRollback logicalPath before 0o644 after 0o644 before after
            write validate activate

    [<Test>]
    member _.``Fresh confirmation commits the journaled candidate``() =
        withHost (fun environment root ->
            writeFile root logicalPath before 0o644
            let value = journal owner (Some before) (Some before)
            let nonce = transact environment value (Some before) (Some after) false false
            Assert.That(nonce.Length, Is.EqualTo 32)
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo after)
            let journalPath = physical root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            FirewalldLifecycle.confirm environment configuration value nonce
            Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None)
            use stored = JsonDocument.Parse(File.ReadAllText journalPath)
            Assert.That(stored.RootElement.GetProperty("pending").ValueKind, Is.EqualTo JsonValueKind.Null)
            Assert.That(stored.RootElement.GetProperty("managed").GetString(), Is.EqualTo after)
            let next = "<zone><service name=\"ssh\"/><port port=\"443\" protocol=\"tcp\"/><port port=\"8443\" protocol=\"tcp\"/></zone>\n"
            let nextNonce = transact environment value (Some after) (Some next) false false
            FirewalldLifecycle.confirm environment configuration value nextNonce
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo next))

    [<Test>]
    member _.``Host-global pending transaction rejects a competing resource``() =
        withHost (fun environment root ->
            writeFile root logicalPath before 0o644
            let value = journal owner (Some before) (Some before)
            transact environment value (Some before) (Some after) false false |> ignore
            let otherConfiguration = FirewalldModel.empty "zone" "other"
            let otherPath = "/etc/firewalld/zones/other.xml"
            let otherValue = journal "other-owner" None None
            let otherWrite contents mode =
                match contents with
                | Some text -> writeFile root otherPath text mode
                | None -> ()
            let failure =
                Assert.Throws<InvalidOperationException>(fun () ->
                    FirewalldLifecycle.transact environment otherConfiguration otherValue true otherPath None 0o644 (Some "<zone/>\n") 0o644 None (Some "<zone/>\n") otherWrite (fun _ -> ()) (fun () -> ()) |> ignore)
            Assert.That(failure.Message, Does.Contain "Another firewalld transaction"))

    [<TestCase(0o600)>]
    [<TestCase(0o640)>]
    [<TestCase(0o644)>]
    member _.``Safe override modes survive apply and watchdog rollback``(mode: int) =
        withHost (fun environment root ->
            let target = physical root logicalPath
            writeFile root logicalPath before mode
            let value = journal owner (Some before) (Some before)
            value["baselineMode"] <- JsonValue.Create mode
            value["managedMode"] <- JsonValue.Create mode
            let write contents writtenMode =
                match contents with
                | Some text -> writeFile root logicalPath text writtenMode
                | None -> if File.Exists target then File.Delete target
            let nonce =
                FirewalldLifecycle.transact
                    environment configuration value false logicalPath (Some before) mode (Some after) mode
                    (Some before) (Some after) write (fun _ -> ()) (fun () -> ())
            Assert.That(nonce, Is.Not.Empty)
            Assert.That(int (File.GetUnixFileMode target), Is.EqualTo mode)
            FirewalldLifecycle.recoverPending environment (fun transaction storedJournal ->
                let journal = storedJournal |> Option.defaultWith (fun () -> failwith "Expected owner journal")
                FirewalldLifecycle.recoverPendingTransaction environment transaction.Configuration journal transaction.Path write (fun () -> ()))
            Assert.That(File.ReadAllText target, Is.EqualTo before)
            Assert.That(int (File.GetUnixFileMode target), Is.EqualTo mode))

    [<Test>]
    member _.``Independent recovery restores exact pre-delete bytes after confirmation is lost``() =
        withHost (fun environment root ->
            writeFile root logicalPath before 0o644
            let value = journal owner (Some before) (Some before)
            let nonce = transact environment value (Some before) (Some after) false false
            Assert.That(nonce, Is.Not.Empty)
            let journalPath = physical root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            FirewalldLifecycle.recoverPending environment (fun transaction storedJournal ->
                let journal = storedJournal |> Option.defaultWith (fun () -> failwith "Expected owner journal")
                let write contents mode =
                    match contents with
                    | Some text -> writeFile root transaction.Path text mode
                    | None -> ()
                FirewalldLifecycle.recoverPendingTransaction environment transaction.Configuration journal transaction.Path write (fun () -> ()))
            Assert.That(File.ReadAllText(physical root logicalPath), Is.EqualTo before)
            Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None)
            use recovered = JsonDocument.Parse(File.ReadAllText journalPath)
            Assert.That(recovered.RootElement.GetProperty("managed").GetString(), Is.EqualTo before)
            Assert.That(recovered.RootElement.GetProperty("pending").ValueKind, Is.EqualTo JsonValueKind.Null))

    [<Test>]
    member _.``Delete confirmation releases only its own journal after exact baseline restore``() =
        withHost (fun environment root ->
            let target = physical root logicalPath
            let baseline = "<zone target=\"DROP\"><interface name=\"eth0\"/></zone>\n"
            let managed = "<zone target=\"DROP\"/>\n"
            writeFile root logicalPath managed 0o644
            let value = journal owner (Some baseline) (Some managed)
            value["baselineMode"] <- JsonValue.Create 0o644
            let journalPath = physical root "/var/lib/keroosha-iac/firewalld/zone-lifecycle.json"
            let nonce = transact environment value (Some managed) (Some baseline) false true
            Assert.That(nonce, Is.Not.Empty)
            Assert.That(File.ReadAllText target, Is.EqualTo baseline)
            FirewalldLifecycle.confirm environment configuration value nonce
            Assert.That(File.Exists journalPath, Is.False)
            Assert.That(FirewalldLifecycle.pending environment, Is.EqualTo None)
            Assert.That(File.ReadAllText target, Is.EqualTo baseline))

    [<Test>]
    member _.``Populated split zones are refused before mutation``() =
        withHost (fun environment root ->
            let directory = physical root "/usr/lib/firewalld/zones/public"
            Directory.CreateDirectory directory |> ignore
            File.WriteAllText(Path.Combine(directory, "20-local.xml"), "<zone><service name=\"ssh\"/></zone>")
            Assert.Throws<Dorothy.HostHelper.Firewalld.BackendError>(fun () ->
                Dorothy.HostHelper.Firewalld.ensureNoSplitZones environment) |> ignore)
