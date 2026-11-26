namespace Dorothy.Tests

open System
open Dorothy.HostHelper
open NUnit.Framework

[<TestFixture>]
type FirewalldDockerGateTests() =
    // A policy can be quiet until Docker binds its bridge. Query named loaded policies,
    // not just the active list. Input shape is firewall-cmd 2.3.1 --policy=NAME --list-all.
    let observe name ingress egress target priority ports =
        let text =
            String.concat "\n"
                [ name; "  priority: " + string priority; "  target: " + target; "  ingress-zones: " + ingress; "  egress-zones: " + egress
                  "  services:"; "  ports: " + ports; "  protocols:"; "  masquerade: no"; "  forward-ports:"; "  source-ports:"; "  icmp-blocks:"; "  rich rules:" ]
        let env = { HostEnvironment.system with
                        Run = fun exe args _ ->
                            if exe <> "firewall-cmd" || args <> ["--policy=" + name; "--list-all"] then invalidOp "Unexpected runtime query."
                            { ExitCode = 0; Stdout = text; Stderr = "" } }
        FirewalldRuntime.inspectRuntime env "policy" name |> Option.get

    [<Test>]
    member _.``External policy cannot precede a Docker DROP while HOST authorization remains unrelated``() =
        let fence = FirewalldGateModel.parseArguments "dockerguard" "-10" "public" "docker"
        let guard = observe "dockerguard" "public" "docker" "DROP" -10 ""
        let verify other = FirewalldDockerGate.verifyPolicies [guard; other] [fence]
        verify (observe "hostapi" "public" "HOST" "ACCEPT" -20 "")
        verify (observe "defaultallow" "ANY" "docker" "ACCEPT" 32767 "")
        for priority in [-20; -10] do
            let overlapping = observe "external" "ANY" "docker" "CONTINUE" priority "8443/tcp"
            Assert.Throws<Firewalld.BackendError>(fun () -> verify overlapping) |> ignore
        let permeable = {guard with Ports=["8443/tcp"]}
        Assert.Throws<Firewalld.BackendError>(fun () -> FirewalldDockerGate.verifyPolicies [permeable] [fence]) |> ignore
