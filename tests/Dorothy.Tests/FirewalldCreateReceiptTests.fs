namespace Dorothy.Tests

open System
open System.IO
open Dorothy.DSL
open Dorothy.DSL.Provider
open NUnit.Framework

[<TestFixture; NonParallelizable>]
type FirewalldCreateReceiptTests() =
    let withReceiptHome (action: string -> unit) =
        let home = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-receipts-" + Guid.NewGuid().ToString("N"))
        let oldHome = Environment.GetEnvironmentVariable "PULUMI_HOME"
        Environment.SetEnvironmentVariable("PULUMI_HOME", home)
        try action home
        finally
            Environment.SetEnvironmentVariable("PULUMI_HOME", oldHome)
            if Directory.Exists home then Directory.Delete(home, true)

    let urn = Pulumi.Urn("urn:pulumi:unit::unit::keroosha:debian:FirewalldZone::receipt")
    let token = FirewalldProvider.ZoneToken
    let connection =
        { Address = "192.0.2.40"; User = "root"; Port = 22; IdentityFile = Some "/private/ssh/key" }
    let configuration = FirewalldModel.empty "zone" "receipt" |> FirewalldModel.toJson

    [<Test>]
    member _.``Each Create has a unique private ticket and only exact owner import works``() =
        withReceiptHome (fun _ ->
            let first = FirewalldCreateReceipts.create urn token connection configuration
            let second = FirewalldCreateReceipts.create urn token connection configuration
            Assert.That(first.OwnerId, Is.Not.EqualTo second.OwnerId)
            Assert.That(first.Ticket, Is.Not.EqualTo second.Ticket)
            Assert.That(first.OwnerId.EndsWith("::" + first.Ticket, StringComparison.Ordinal), Is.True)
            let firstPath = FirewalldCreateReceipts.pathForTicket first.Ticket
            let secondPath = FirewalldCreateReceipts.pathForTicket second.Ticket
            if not (OperatingSystem.IsWindows()) then
                Assert.That(int (File.GetUnixFileMode firstPath), Is.EqualTo 0o600)
                Assert.That(int (File.GetUnixFileMode(Path.GetDirectoryName firstPath)), Is.EqualTo 0o700)
            let imported = FirewalldCreateReceipts.readTicket urn token (FirewalldCreateReceipts.importId first)
            Assert.That(imported.OwnerId, Is.EqualTo first.OwnerId)
            Assert.That(File.Exists firstPath, Is.True)
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldCreateReceipts.readTicket (Pulumi.Urn("urn:pulumi:other::unit::keroosha:debian:FirewalldZone::receipt")) token
                    (FirewalldCreateReceipts.importId first)
                |> ignore)
            |> ignore
            FirewalldCreateReceipts.acknowledgeOwner urn token first.OwnerId
            Assert.That(File.Exists firstPath, Is.False)
            Assert.That(File.Exists secondPath, Is.True))

    [<Test>]
    member _.``Invalid local receipt is retained and cannot invalidate remote acknowledgement``() =
        withReceiptHome (fun _ ->
            let receipt = FirewalldCreateReceipts.create urn token connection configuration
            let path = FirewalldCreateReceipts.pathForTicket receipt.Ticket
            File.WriteAllText(path, "not a receipt")
            FirewalldCreateReceipts.acknowledgeOwner urn token receipt.OwnerId
            Assert.That(File.ReadAllText(path), Is.EqualTo "not a receipt")
            Assert.That((fun () -> FirewalldCreateReceipts.readTicket urn token (FirewalldCreateReceipts.importId receipt) |> ignore),
                        Throws.InstanceOf<System.Text.Json.JsonException>()))

    [<Test>]
    member _.``Only a strict authenticated pre-stage envelope retires its exact receipt``() =
        withReceiptHome (fun _ ->
            let receipt = FirewalldCreateReceipts.create urn token connection configuration
            let refusal = Dorothy.HostHelper.Firewalld.PreStageRefusal("apply", receipt.OwnerId, "baseline cannot be adopted safely")
            let response = Dorothy.HostHelper.Program.serializePreStageRefusal refusal
            use document = System.Text.Json.JsonDocument.Parse(response.ToJsonString())
            Assert.Throws<FirewalldPreStageRefusalException>(fun () ->
                FirewalldBackend.validatePreStageEnvelope "apply" receipt.OwnerId document.RootElement)
            |> ignore
            FirewalldCreateReceipts.acknowledgeOwner urn token receipt.OwnerId
            Assert.That(File.Exists(FirewalldCreateReceipts.pathForTicket receipt.Ticket), Is.False))

    [<Test>]
    member _.``Missing or mismatched pre-stage envelopes preserve the recovery receipt``() =
        withReceiptHome (fun _ ->
            let receipt = FirewalldCreateReceipts.create urn token connection configuration
            let path = FirewalldCreateReceipts.pathForTicket receipt.Ticket
            use missing = System.Text.Json.JsonDocument.Parse("{\"unchanged\":true}")
            FirewalldBackend.validatePreStageEnvelope "apply" receipt.OwnerId missing.RootElement
            Assert.That(File.Exists path, Is.True)
            let mismatch =
                Dorothy.HostHelper.Program.serializePreStageRefusal(
                    Dorothy.HostHelper.Firewalld.PreStageRefusal("apply", "unrelated-owner", "baseline refused")
                )
            use mismatched = System.Text.Json.JsonDocument.Parse(mismatch.ToJsonString())
            Assert.Throws<InvalidOperationException>(fun () ->
                FirewalldBackend.validatePreStageEnvelope "apply" receipt.OwnerId mismatched.RootElement)
            |> ignore
            Assert.That(File.Exists path, Is.True))

    [<Test>]
    member _.``Ambiguous Create error exposes only the exact recovery ticket and safe failure summary``() =
        withReceiptHome (fun _ ->
            let receipt = FirewalldCreateReceipts.create urn token connection configuration
            let raw =
                String.concat " "
                    [ "SSH operation failed for"
                      urn.ToString()
                      connection.Address
                      connection.User
                      string connection.Port
                      configuration
                      receipt.OwnerId
                      "identity=" + connection.IdentityFile.Value
                      "fingerprint=SHA256:AAABBBCCC" ]
            let message = FirewalldCreateReceipts.recoveryFailureMessage receipt (InvalidOperationException(raw))
            Assert.That(message, Does.Contain(FirewalldCreateReceipts.importId receipt))
            Assert.That(message, Does.Contain "pulumi import --protect=false")
            Assert.That(message, Does.Not.Contain(urn.ToString()))
            Assert.That(message, Does.Not.Contain(connection.Address))
            Assert.That(message, Does.Not.Contain(connection.IdentityFile.Value))
            Assert.That(message, Does.Not.Contain(configuration))
            Assert.That(message, Does.Not.Contain(receipt.OwnerId))
            Assert.That(message, Does.Not.Contain "SHA256:AAABBBCCC")
            Assert.That(message, Does.Contain "SSH operation failed"))
