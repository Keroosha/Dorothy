namespace Dorothy.Tests

open System
open System.IO
open NUnit.Framework
open Dorothy.HostHelper

module BindingTransferNative = Dorothy.HostHelper.Firewalld

[<TestFixture; NonParallelizable>]
type FirewalldBindingTransferTests() =
    let sshConnection = "203.0.113.2 49200 198.51.100.2 22"
    let sourceSelector = "192.0.2.0/24"
    let sourceZone = "<zone target=\"DROP\"><source address=\"192.0.2.0/24\"/></zone>"
    let unboundSourceZone = "<zone target=\"DROP\"/>"
    let sshService = "<service><port port=\"22\" protocol=\"tcp\"/></service>"
    let publicOpen = "<zone target=\"ACCEPT\"><port port=\"8080\" protocol=\"tcp\"/></zone>"
    let publicDrop = "<zone target=\"DROP\"/>"
    let managementZone = "<zone target=\"ACCEPT\"><source address=\"203.0.113.0/24\"/><service name=\"ssh\"/></zone>"
    let destinationZone = "<zone target=\"DROP\"/>"
    let proposedSourceRemoval = Some unboundSourceZone

    let ensureDirectory (root: string) (relative: string) =
        Directory.CreateDirectory(Path.Combine(root, relative)) |> ignore

    let write (root: string) (relative: string) (contents: string) =
        let path = Path.Combine(root, relative)
        Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
        File.WriteAllText(path, contents)

    let sourceDrop = sprintf "<rule family=\"ipv4\"><source address=\"%s\"/><drop/></rule>" sourceSelector
    let destinationDrop = sprintf "<rule family=\"ipv4\"><destination address=\"%s\"/><drop/></rule>" sourceSelector

    let stagePolicy (egress: string) =
        let rules = if egress = "ANY" then sourceDrop + destinationDrop else sourceDrop
        sprintf
            "<policy priority=\"-32768\" target=\"CONTINUE\"><ingress-zone name=\"ANY\"/><egress-zone name=\"%s\"/>%s</policy>"
            egress rules

    let addStagePolicies (root: string) =
        write root "etc/firewalld/policies/fence-host.xml" (stagePolicy "HOST")
        write root "etc/firewalld/policies/fence-transit.xml" (stagePolicy "ANY")

    let addOutputStagePolicy (root: string) =
        write root "etc/firewalld/policies/fence-output.xml"
            (sprintf "<policy priority=\"-32768\" target=\"CONTINUE\"><ingress-zone name=\"HOST\"/><egress-zone name=\"ANY\"/><rule family=\"ipv4\"><destination address=\"%s\"/><drop/></rule></policy>" sourceSelector)

    let addRestrictiveOutputPolicy (root: string) =
        write root "etc/firewalld/policies/old-output-drop.xml"
            "<policy priority=\"-10\" target=\"DROP\"><ingress-zone name=\"HOST\"/><egress-zone name=\"source-net\"/></policy>"
        write root "etc/firewalld/policies/public-output.xml"
            "<policy priority=\"-10\" target=\"ACCEPT\"><ingress-zone name=\"HOST\"/><egress-zone name=\"public\"/></policy>"

    let addEarlierAllows (root: string) =
        write root "etc/firewalld/policies/early-host.xml"
            "<policy priority=\"-10\" target=\"CONTINUE\"><ingress-zone name=\"public\"/><egress-zone name=\"HOST\"/><port port=\"8080\" protocol=\"tcp\"/></policy>"
        write root "etc/firewalld/policies/early-transit.xml"
            "<policy priority=\"-10\" target=\"CONTINUE\"><ingress-zone name=\"public\"/><egress-zone name=\"destination-net\"/><port port=\"8080\" protocol=\"tcp\"/></policy>"

    let addTiedPriorityAllow (root: string) =
        write root "etc/firewalld/policies/tied-host.xml"
            "<policy priority=\"-32768\" target=\"CONTINUE\"><ingress-zone name=\"public\"/><egress-zone name=\"HOST\"/><port port=\"8080\" protocol=\"tcp\"/></policy>"
    let createRoot (root: string) (fallbackZone: string) =
        for directory in [ "usr/lib/firewalld"; "usr/lib/firewalld/zones"; "usr/lib/firewalld/services";
                           "etc/firewalld"; "etc/firewalld/zones"; "etc/firewalld/policies" ] do
            ensureDirectory root directory
        write root "usr/lib/firewalld/firewalld.conf" "DefaultZone=public\n"
        write root "usr/lib/firewalld/zones/public.xml" fallbackZone
        write root "usr/lib/firewalld/zones/source-net.xml" unboundSourceZone
        write root "usr/lib/firewalld/zones/destination-net.xml" destinationZone
        write root "usr/lib/firewalld/zones/management.xml" managementZone
        write root "usr/lib/firewalld/services/ssh.xml" sshService
        write root "etc/firewalld/zones/source-net.xml" sourceZone

    let environment (root: string) : HostEnvironment =
        let native = FirewalldCommandFixture.commands root
        let run executable arguments _ : CommandResult =
            match executable, arguments with
            | "ip", _ -> { ExitCode = 0; Stdout = "[{\"dev\":\"eth0\"}]"; Stderr = "" }
            | "firewall-cmd", [ "--get-zone-of-interface=eth0" ] ->
                match native executable arguments with
                | Some output when output.Trim() = "no zone" -> { ExitCode = 2; Stdout = "no zone"; Stderr = "" }
                | Some output -> { ExitCode = 0; Stdout = output; Stderr = "" }
                | None -> failwith "Missing firewalld interface-zone fixture."
            | _ ->
                match native executable arguments with
                | Some output -> { ExitCode = 0; Stdout = output; Stderr = "" }
                | None -> failwith ("Unexpected binding-transfer fixture command: " + executable + " " + String.concat " " arguments)
        TestSupport.fakeHostEnvironment root run (fun () -> DateTimeOffset.UnixEpoch)

    let zoneConfiguration = FirewalldModel.empty "zone" "source-net"

    let withSsh (action: unit -> unit) =
        let previous = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        try
            Environment.SetEnvironmentVariable("SSH_CONNECTION", sshConnection)
            action ()
        finally
            Environment.SetEnvironmentVariable("SSH_CONNECTION", previous)

    let assertBlocked (environment: HostEnvironment) (proposed: string option) =
        let error =
            Assert.Throws<BindingTransferNative.BackendError>(TestDelegate(fun () ->
                BindingTransferNative.guardMutation environment zoneConfiguration proposed))
        Assert.That(error.Message, Does.Contain("Refusing to remove firewalld source binding"))

    [<Test>]
    member _.``An open fallback refuses source removal before changing the managed zone``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-open-")
        createRoot temporary.Path publicOpen
        let environment = environment temporary.Path
        withSsh (fun () ->
            let before = File.ReadAllText(Path.Combine(temporary.Path, "etc/firewalld/zones/source-net.xml"))
            assertBlocked environment proposedSourceRemoval
            Assert.That(File.ReadAllText(Path.Combine(temporary.Path, "etc/firewalld/zones/source-net.xml")), Is.EqualTo(before)))

    [<Test>]
    member _.``A restrictive fallback allows source removal without an unnecessary staging policy``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-drop-")
        createRoot temporary.Path publicDrop
        let environment = environment temporary.Path
        withSsh (fun () ->
            Assert.DoesNotThrow(TestDelegate(fun () ->
                BindingTransferNative.guardMutation environment zoneConfiguration proposedSourceRemoval)))

    [<Test>]
    member _.``A confirmed earliest source fence covers host and transit policies before source removal``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-staged-")
        createRoot temporary.Path publicOpen
        addStagePolicies temporary.Path
        addEarlierAllows temporary.Path
        let environment = environment temporary.Path
        withSsh (fun () ->
            Assert.DoesNotThrow(TestDelegate(fun () ->
                BindingTransferNative.guardMutation environment zoneConfiguration proposedSourceRemoval)))

    [<Test>]
    member _.``A tied minimum-priority fallback policy prevents staged removal``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-priority-tie-")
        createRoot temporary.Path publicOpen
        addStagePolicies temporary.Path
        addTiedPriorityAllow temporary.Path
        let environment = environment temporary.Path
        withSsh (fun () -> assertBlocked environment proposedSourceRemoval)


    [<Test>]
    member _.``Contiguous dotted IPv4 masks match equivalent numeric staging fences``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-dotted-mask-")
        createRoot temporary.Path publicOpen
        write temporary.Path "etc/firewalld/zones/source-net.xml"
            "<zone target=\"DROP\"><source address=\"192.0.2.0/255.255.255.0\"/></zone>"
        addStagePolicies temporary.Path
        let environment = environment temporary.Path
        withSsh (fun () ->
            Assert.DoesNotThrow(TestDelegate(fun () ->
                BindingTransferNative.guardMutation environment zoneConfiguration proposedSourceRemoval)))

    [<Test>]
    member _.``A matching fallback forward-port cannot be covered by filter staging``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-nat-")
        createRoot temporary.Path
            "<zone target=\"ACCEPT\"><forward-port port=\"8080\" protocol=\"tcp\" to-addr=\"198.51.100.10\"/></zone>"
        addStagePolicies temporary.Path
        let environment = environment temporary.Path
        withSsh (fun () ->
            let error =
                Assert.Throws<BindingTransferNative.BackendError>(TestDelegate(fun () ->
                    BindingTransferNative.guardMutation environment zoneConfiguration proposedSourceRemoval))
            Assert.That(error.Message, Does.Contain("before normal filter dispatch")))


    [<Test>]
    member _.``A fallback rich forward-port disjoint from the moving subnet does not block a staged handoff``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-nat-disjoint-")
        createRoot temporary.Path
            "<zone target=\"ACCEPT\"><rule family=\"ipv4\"><source address=\"198.51.100.0/24\"/><forward-port port=\"8080\" protocol=\"tcp\" to-addr=\"198.51.100.10\"/></rule></zone>"
        addStagePolicies temporary.Path
        let environment = environment temporary.Path
        withSsh (fun () ->
            Assert.DoesNotThrow(TestDelegate(fun () ->
                BindingTransferNative.guardMutation environment zoneConfiguration proposedSourceRemoval)))
    [<Test>]
    member _.``A restrictive host egress policy requires a destination fence``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-egress-blocked-")
        createRoot temporary.Path publicOpen
        addStagePolicies temporary.Path
        addRestrictiveOutputPolicy temporary.Path
        let environment = environment temporary.Path
        withSsh (fun () -> assertBlocked environment proposedSourceRemoval)

    [<Test>]
    member _.``A confirmed host egress destination fence permits a restrictive output-policy handoff``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-egress-staged-")
        createRoot temporary.Path publicOpen
        addStagePolicies temporary.Path
        addRestrictiveOutputPolicy temporary.Path
        addOutputStagePolicy temporary.Path
        let environment = environment temporary.Path
        withSsh (fun () ->
            Assert.DoesNotThrow(TestDelegate(fun () ->
                BindingTransferNative.guardMutation environment zoneConfiguration proposedSourceRemoval)))

    
    [<Test>]
    member _.``A permanent but inactive source fence cannot authorize removal``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-inactive-")
        createRoot temporary.Path publicOpen
        let environment = environment temporary.Path
        // Freeze the fixture's daemon view before adding the permanent staging policies.
        environment.Run "firewall-cmd" [ "--get-zones" ] None |> ignore
        addStagePolicies temporary.Path
        withSsh (fun () -> assertBlocked environment proposedSourceRemoval)


    [<Test>]
    member _.``An open unbound subnet cannot lose its active staging fence``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-unbound-cleanup-")
        createRoot temporary.Path publicOpen
        addStagePolicies temporary.Path
        let environment = environment temporary.Path
        write temporary.Path "etc/firewalld/zones/source-net.xml" unboundSourceZone
        environment.Run "firewall-cmd" [ "--reload" ] None |> ignore
        withSsh (fun () ->
            let policy = FirewalldModel.empty "policy" "fence-host"
            let error =
                Assert.Throws<BindingTransferNative.BackendError>(TestDelegate(fun () ->
                    BindingTransferNative.guardMutation environment policy None))
            Assert.That(error.Message, Does.Contain("transfer fence")))

    [<Test>]
    member _.``An open unbound subnet cannot weaken its active staging fence``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-weakened-cleanup-")
        createRoot temporary.Path publicOpen
        addStagePolicies temporary.Path
        let environment = environment temporary.Path
        write temporary.Path "etc/firewalld/zones/source-net.xml" unboundSourceZone
        environment.Run "firewall-cmd" [ "--reload" ] None |> ignore
        withSsh (fun () ->
            let policy = FirewalldModel.empty "policy" "fence-host"
            let weaker = Some "<policy priority=\"-1\" target=\"CONTINUE\"><ingress-zone name=\"ANY\"/><egress-zone name=\"HOST\"/></policy>"
            let error =
                Assert.Throws<BindingTransferNative.BackendError>(TestDelegate(fun () ->
                    BindingTransferNative.guardMutation environment policy weaker))
            Assert.That(error.Message, Does.Contain("transfer fence")))
    [<Test>]

    member _.``Deleting staging policies after the destination binding is active is an ordinary cleanup``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-cleanup-")
        createRoot temporary.Path publicOpen
        addStagePolicies temporary.Path
        let environment = environment temporary.Path
        withSsh (fun () ->
            Assert.DoesNotThrow(TestDelegate(fun () ->
                BindingTransferNative.guardMutation environment zoneConfiguration proposedSourceRemoval))
            write temporary.Path "etc/firewalld/zones/source-net.xml" unboundSourceZone
            write temporary.Path "etc/firewalld/zones/destination-net.xml"
                "<zone target=\"DROP\"><source address=\"192.0.2.0/24\"/></zone>"
            environment.Run "firewall-cmd" [ "--reload" ] None |> ignore
            for name in [ "fence-host"; "fence-transit" ] do
                let policy = FirewalldModel.empty "policy" name
                Assert.DoesNotThrow(TestDelegate(fun () -> BindingTransferNative.guardMutation environment policy None)))

    [<Test>]
    member _.``Delete restoring a vendor zone also guards the removed source binding``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-vendor-delete-")
        createRoot temporary.Path publicOpen
        let environment = environment temporary.Path
        withSsh (fun () -> assertBlocked environment None)

    [<Test>]
    member _.``Delete restoring a vendor zone succeeds with a restrictive fallback``() =
        use temporary = new TemporaryDirectory("dorothy-firewalld-binding-vendor-drop-")
        createRoot temporary.Path publicDrop
        let environment = environment temporary.Path
        withSsh (fun () ->
            Assert.DoesNotThrow(TestDelegate(fun () ->
                BindingTransferNative.guardMutation environment zoneConfiguration None)))

    [<Test>]
    member _.``A permit to the fallback invalidates a blanket-DROP release proof``() =
        use temporary = new TemporaryDirectory("dorothy-source-reverse-")
        createRoot temporary.Path publicDrop
        write temporary.Path "etc/firewalld/policies/reverse.xml"
            "<policy priority=\"-5\" target=\"ACCEPT\"><ingress-zone name=\"destination-net\"/><egress-zone name=\"public\"/></policy>"
        withSsh (fun () -> assertBlocked (environment temporary.Path) proposedSourceRemoval)

    [<Test>]
    member _.``Shrinking a bound hash net set uses the source transfer fences``() =
        let zone = "<zone target=\"DROP\"><source ipset=\"clients\"/></zone>"
        let zones = Map.ofList [ "source-net", zone; "public", publicOpen ]
        let old = Some "<ipset type=\"hash:net\"><entry>192.0.2.0/24</entry></ipset>"
        let empty = Some "<ipset type=\"hash:net\"/>"
        let transition policies =
            FirewalldBindingTransfer.validateBoundSet "clients" old empty old zones policies "public" "public" zones policies
        Assert.That(Result.isError (transition Map.empty), Is.True)
        let fences = Map.ofList [ "fence-h", stagePolicy "HOST"; "fence-t", stagePolicy "ANY" ]
        Assert.That(transition fences, Is.EqualTo(Ok () : Result<unit, string>))

    [<Test>]
    member _.``An interface cannot be released through a more permissive default``() =
        let before = "<zone target=\"DROP\"><interface name=\"app0\"/></zone>"
        let run fallback =
            let after = Map.ofList [ "source-net", unboundSourceZone; "public", fallback ]
            FirewalldBindingTransfer.validate (Some(set ["app0"])) zoneConfiguration (Some before) after Map.empty "public" "public" (Map.add "source-net" before after) Map.empty
        Assert.That(Result.isError (run publicOpen), Is.True)
        Assert.That(run publicDrop, Is.EqualTo(Ok () : Result<unit, string>))
