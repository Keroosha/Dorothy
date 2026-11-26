namespace Dorothy.Tests

open System
open System.IO
open NUnit.Framework
open Dorothy.HostHelper

module FirewalldGuardNative = Dorothy.HostHelper.Firewalld

[<TestFixture; NonParallelizable>]
type FirewalldGuardTests() =
    let context = FirewalldGuardNative.parseSshContext "192.0.2.1 49200 192.0.2.2 22" "[{\"dev\":\"eth0\"}]"
    let sshService = "<service><port port=\"22\" protocol=\"tcp\"/></service>"
    let safeZone = "<zone><interface name=\"eth0\"/><service name=\"ssh\"/></zone>"
    let services = Map.ofList [ "ssh", sshService ]
    let validate zones policies ipsets serviceDefinitions =
        FirewalldGuardNative.validateSshGuardWithDefinitions
            context "public" zones policies ipsets serviceDefinitions
    let expectDenied action =
        Assert.Throws<FirewalldGuardNative.BackendError>(TestDelegate action) |> ignore

    [<Test>]
    member _.``Guard matches peer and local ports and proves disjoint family and source port``() =
        let drop sourcePort family address =
            sprintf "<rule family=\"%s\"><source address=\"%s\"/><source-port port=\"%s\" protocol=\"tcp\"/><port port=\"22\" protocol=\"tcp\"/><drop/></rule>" family address sourcePort
        let zone rule = "<zone><interface name=\"eth0\"/><service name=\"ssh\"/>" + rule + "</zone>"
        validate (Map.ofList [ "public", zone (drop "49201" "ipv4" "192.0.2.0/24") ]) Map.empty Map.empty services
        validate (Map.ofList [ "public", zone (drop "49200" "ipv6" "2001:db8::/32") ]) Map.empty Map.empty services
        validate (Map.ofList [ "public", zone (drop "49200" "ipv4" "198.51.100.0/24") ]) Map.empty Map.empty services
        expectDenied (fun () -> validate (Map.ofList [ "public", zone (drop "49200" "ipv4" "192.0.2.0/24") ]) Map.empty Map.empty services)

    [<Test>]
    member _.``DNAT blocks only a matching inbound management tuple``() =
        let forward family source port =
            sprintf "<rule family=\"%s\"><source address=\"%s\"/><forward-port port=\"%s\" protocol=\"tcp\" to-addr=\"198.51.100.8\"/></rule>" family source port
        let zone rule = "<zone><interface name=\"eth0\"/><service name=\"ssh\"/>" + rule + "</zone>"
        validate (Map.ofList [ "public", zone (forward "ipv4" "198.51.100.0/24" "22") ]) Map.empty Map.empty services
        validate (Map.ofList [ "public", zone (forward "ipv4" "192.0.2.0/24" "2222") ]) Map.empty Map.empty services
        validate (Map.ofList [ "public", zone (forward "ipv6" "2001:db8::/32" "22") ]) Map.empty Map.empty services
        expectDenied (fun () -> validate (Map.ofList [ "public", zone (forward "ipv4" "192.0.2.0/24" "22") ]) Map.empty Map.empty services)

    [<Test>]
    member _.``Guard resolves source zones and native suffix-plus interface bindings``() =
        let unrelatedSource = "<zone target=\"DROP\"><source address=\"198.51.100.0/24\"/></zone>"
        validate (Map.ofList [ "public", safeZone; "other", unrelatedSource ]) Map.empty Map.empty services

        let matchingSource = "<zone target=\"DROP\"><source address=\"192.0.2.0/24\"/></zone>"
        expectDenied (fun () -> validate (Map.ofList [ "public", safeZone; "other", matchingSource ]) Map.empty Map.empty services)

        let wildcard = "<zone target=\"DROP\"><interface name=\"eth+\"/></zone>"
        expectDenied (fun () -> validate (Map.ofList [ "public", safeZone; "wildcard", wildcard ]) Map.empty Map.empty services)
        validate (Map.ofList [ "public", safeZone; "unrelated", "<zone target=\"DROP\"><interface name=\"en+\"/></zone>" ]) Map.empty Map.empty services
        expectDenied (fun () -> validate (Map.ofList [ "public", safeZone; "all", "<zone target=\"DROP\"><interface name=\"+\"/></zone>" ]) Map.empty Map.empty services)

    [<Test>]
    member _.``Host-only policies authorize SSH without granting sibling traffic``() =
        let zone = Map.ofList [ "public", "<zone/>" ]
        let authorize =
            "<policy target=\"DROP\" priority=\"-1\"><ingress-zone name=\"public\"/><egress-zone name=\"HOST\"/><port port=\"22\" protocol=\"tcp\"/></policy>"
        validate zone (Map.ofList [ "ssh-host", authorize ]) Map.empty services

        let targetDropWithExplicitSsh =
            "<zone target=\"DROP\"><interface name=\"eth0\"/><port port=\"22\" protocol=\"tcp\"/></zone>"
        validate (Map.ofList [ "public", targetDropWithExplicitSsh ]) Map.empty Map.empty Map.empty

        let sibling =
            "<policy target=\"DROP\" priority=\"-1\"><ingress-zone name=\"public\"/><egress-zone name=\"HOST\"/><port port=\"2222\" protocol=\"tcp\"/></policy>"
        expectDenied (fun () -> validate zone (Map.ofList [ "sibling", sibling ]) Map.empty services)
        let terminalZone = Map.ofList [ "public", "<zone target=\"DROP\"/>" ]
        let positiveAllow =
            "<policy target=\"ACCEPT\" priority=\"10\"><ingress-zone name=\"public\"/><egress-zone name=\"HOST\"/><port port=\"22\" protocol=\"tcp\"/></policy>"
        expectDenied (fun () -> validate terminalZone (Map.ofList [ "positive-host", positiveAllow ]) Map.empty services)

        let transitAccept =
            "<policy target=\"ACCEPT\" priority=\"-1\"><ingress-zone name=\"public\"/><egress-zone name=\"ANY\"/><port port=\"22\" protocol=\"tcp\"/></policy>"
        expectDenied (fun () -> validate terminalZone (Map.ofList [ "transit", transitAccept ]) Map.empty services)

        let unrelated =
            "<policy target=\"CONTINUE\" priority=\"-1\"><ingress-zone name=\"ANY\"/><egress-zone name=\"HOST\"/><rule family=\"ipv4\"><destination address=\"198.51.100.0/24\"/><port port=\"22\" protocol=\"tcp\"/><drop/></rule></policy>"
        validate (Map.ofList [ "public", safeZone ]) (Map.ofList [ "unrelated", unrelated ]) Map.empty services
 

        let otherEgress =
            "<policy target=\"DROP\"><ingress-zone name=\"public\"/><egress-zone name=\"docker\"/></policy>"
        validate (Map.ofList [ "public", safeZone ]) (Map.ofList [ "docker-only", otherEgress ]) Map.empty services

        let replyRule destinationPort =
            sprintf
                "<policy target=\"CONTINUE\" priority=\"-1\"><ingress-zone name=\"HOST\"/><egress-zone name=\"public\"/><rule family=\"ipv4\"><source address=\"192.0.2.2\"/><source-port port=\"22\" protocol=\"tcp\"/><destination address=\"192.0.2.1\"/><port port=\"%s\" protocol=\"tcp\"/><drop/></rule></policy>"
                destinationPort
        expectDenied (fun () -> validate (Map.ofList [ "public", safeZone ]) (Map.ofList [ "reply-block", replyRule "49200" ]) Map.empty services)
        validate (Map.ofList [ "public", safeZone ]) (Map.ofList [ "other-reply", replyRule "49201" ]) Map.empty services

        let replyDnat =
            "<policy target=\"CONTINUE\" priority=\"-1\"><ingress-zone name=\"HOST\"/><egress-zone name=\"public\"/><rule family=\"ipv4\"><forward-port port=\"49200\" protocol=\"tcp\" to-addr=\"198.51.100.8\"/></rule></policy>"
        validate (Map.ofList [ "public", safeZone ]) (Map.ofList [ "reply-dnat", replyDnat ]) Map.empty services

    [<Test>]
    member _.``Service includes are expanded and cycles fail closed``() =
        let included =
            Map.ofList [ "ssh", "<service><include service=\"ssh-base\"/></service>"
                         "ssh-base", "<service><port port=\"22\" protocol=\"tcp\"/></service>" ]
        validate (Map.ofList [ "public", "<zone><interface name=\"eth0\"/><service name=\"ssh\"/></zone>" ]) Map.empty Map.empty included

        let restricted = Map.add "ssh-base" "<service><destination ipv4=\"192.0.2.99\"/><port port=\"22\" protocol=\"tcp\"/></service>" included
        expectDenied (fun () -> validate (Map.ofList [ "public", "<zone><interface name=\"eth0\"/><service name=\"ssh\"/></zone>" ]) Map.empty Map.empty restricted)

        let cyclic = Map.ofList [ "ssh", "<service><include service=\"base\"/></service>"; "base", "<service><include service=\"ssh\"/></service>" ]
        expectDenied (fun () -> validate (Map.ofList [ "public", "<zone><interface name=\"eth0\"/><service name=\"ssh\"/></zone>" ]) Map.empty Map.empty cyclic)

    [<Test>]
    member _.``IPset membership and inverted address selectors are evaluated against the peer``() =
        let withRule rule = "<zone><interface name=\"eth0\"/><service name=\"ssh\"/>" + rule + "</zone>"
        let ipsetRule = "<rule family=\"ipv4\"><source ipset=\"management-peers\"/><drop/></rule>"
        let matchingSet = Map.ofList [ "management-peers", "<ipset type=\"hash:net\"><option name=\"family\" value=\"inet\"/><entry>192.0.2.0/24</entry></ipset>" ]
        let unrelatedSet = Map.ofList [ "management-peers", "<ipset type=\"hash:net\"><option name=\"family\" value=\"inet\"/><entry>198.51.100.0/24</entry></ipset>" ]
        expectDenied (fun () -> validate (Map.ofList [ "public", withRule ipsetRule ]) Map.empty matchingSet services)
        validate (Map.ofList [ "public", withRule ipsetRule ]) Map.empty unrelatedSet services
        expectDenied (fun () -> validate (Map.ofList [ "public", withRule ipsetRule ]) Map.empty Map.empty services)

        let inverted = "<rule family=\"ipv4\"><source address=\"198.51.100.1\" invert=\"true\"/><destination address=\"192.0.2.99\" invert=\"true\"/><drop/></rule>"
        expectDenied (fun () -> validate (Map.ofList [ "public", withRule inverted ]) Map.empty Map.empty services)

    [<Test>]
    member _.``Protocol-only services are uncertain grants but disjoint UDP rules remain harmless``() =
        let protocolOnly = Map.ofList [ "ssh", "<service><protocol value=\"tcp\"/></service>" ]
        let zoneWithSsh = Map.ofList [ "public", "<zone><interface name=\"eth0\"/><service name=\"ssh\"/></zone>" ]
        expectDenied (fun () -> validate zoneWithSsh Map.empty Map.empty protocolOnly)

        let udpService = Map.add "udp-only" "<service><protocol value=\"udp\"/></service>" services
        let disjointRule = "<rule family=\"ipv4\"><service name=\"udp-only\"/><drop/></rule>"
        validate (Map.ofList [ "public", "<zone><interface name=\"eth0\"/><service name=\"ssh\"/>" + disjointRule + "</zone>" ]) Map.empty Map.empty udpService

    [<Test>]
    member _.``Effective runtime host policies are checked independently of permanent state``() =
        let root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-runtime-guard-" + Guid.NewGuid().ToString("N"))
        let previous = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        let runtimeZone =
            "public\n  target: default\n  ingress-priority: 0\n  egress-priority: 0\n  icmp-block-inversion: no\n  interfaces:\n  sources:\n  services: ssh\n  ports:\n  protocols:\n  forward: no\n  masquerade: no\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n"
        let runtimeSourceZone =
            "source-net\n  target: default\n  ingress-priority: 0\n  egress-priority: 0\n  icmp-block-inversion: no\n  interfaces:\n  sources: 192.0.2.0/24\n  services: ssh\n  ports:\n  protocols:\n  forward: no\n  masquerade: no\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n"
        let mutable runtimePolicy =
            "runtime-block\n  priority: -1\n  target: DROP\n  ingress-zones: ANY\n  egress-zones: HOST\n  services:\n  ports:\n  protocols:\n  masquerade: no\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n"
        try
            for directory in [ "usr/lib/firewalld/zones"; "usr/lib/firewalld/services"; "run/lock" ] do
                Directory.CreateDirectory(Path.Combine(root, directory)) |> ignore
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/firewalld.conf"), "DefaultZone=public\n")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/public.xml"), "<zone><service name=\"ssh\"/></zone>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/source-net.xml"), "<zone><source address=\"192.0.2.0/24\"/><service name=\"ssh\"/></zone>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/services/ssh.xml"), sshService)
            Environment.SetEnvironmentVariable("SSH_CONNECTION", "192.0.2.1 49200 192.0.2.2 22")
            let run executable arguments _ : CommandResult =
                match executable, arguments with
                | "ip", _ -> { ExitCode = 0; Stdout = "[{\"dev\":\"eth0\"}]"; Stderr = "" }
                | "firewall-cmd", [ "--get-default-zone" ] -> { ExitCode = 0; Stdout = "public"; Stderr = "" }
                | "firewall-cmd", [ "--get-zone-of-interface=eth0" ] -> { ExitCode = 2; Stdout = "no zone"; Stderr = "" }
                | "firewall-cmd", [ "--get-zones" ] -> { ExitCode = 0; Stdout = "public source-net"; Stderr = "" }
                | "firewall-cmd", [ "--get-policies" ] -> { ExitCode = 0; Stdout = "runtime-block"; Stderr = "" }
                | "firewall-cmd", [ "--zone=public"; "--list-all" ] -> { ExitCode = 0; Stdout = runtimeZone; Stderr = "" }
                | "firewall-cmd", [ "--zone=source-net"; "--list-all" ] -> { ExitCode = 0; Stdout = runtimeSourceZone; Stderr = "" }
                | "firewall-cmd", [ "--policy=runtime-block"; "--list-all" ] -> { ExitCode = 0; Stdout = runtimePolicy; Stderr = "" }
                | _ -> failwith "Unexpected firewalld guard fixture command."
            let environment: HostEnvironment =
                { Root = root; Run = run; UtcNow = fun () -> DateTimeOffset.UnixEpoch }
            let configuration =
                { FirewalldModel.empty "settings" "LogDenied" with SettingValue = Some "all" }
            Assert.Throws<FirewalldGuardNative.BackendError>(TestDelegate(fun () ->
                FirewalldGuardNative.guardMutation environment configuration (Some "DefaultZone=public\nLogDenied=all\n"))) |> ignore
            runtimePolicy <- "runtime-block\n  priority: -1\n  target: CONTINUE\n  ingress-zones: ANY\n  egress-zones: HOST\n  services:\n  ports:\n  protocols:\n  masquerade: no\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n\t\trule family=\"ipv4\" source NOT address=\"192.0.2.0/24\" drop\n"
            Assert.DoesNotThrow(TestDelegate(fun () ->
                FirewalldGuardNative.guardMutation environment configuration (Some "DefaultZone=public\nLogDenied=all\n")))
        finally
            Environment.SetEnvironmentVariable("SSH_CONNECTION", previous)
            if Directory.Exists root then Directory.Delete(root, true)
    [<Test>]
    member _.``DefaultZone settings candidates are guarded before activation``() =
        let root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-guard-" + Guid.NewGuid().ToString("N"))
        let previous = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        try
            for directory in [ "usr/lib/firewalld/zones"; "usr/lib/firewalld/services"; "run/lock" ] do
                Directory.CreateDirectory(Path.Combine(root, directory)) |> ignore
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/firewalld.conf"), "DefaultZone=public\n")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/public.xml"), "<zone><service name=\"ssh\"/></zone>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/isolated.xml"), "<zone target=\"DROP\"/>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/services/ssh.xml"), sshService)
            Environment.SetEnvironmentVariable("SSH_CONNECTION", "192.0.2.1 49200 192.0.2.2 22")
            let run executable arguments _ : CommandResult =
                match executable, arguments with
                | "ip", _ -> { ExitCode = 0; Stdout = "[{\"dev\":\"eth0\"}]"; Stderr = "" }
                | "firewall-cmd", [ "--get-default-zone" ] -> { ExitCode = 0; Stdout = "public"; Stderr = "" }
                | "firewall-cmd", [ "--get-zone-of-interface=eth0" ] -> { ExitCode = 2; Stdout = "no zone"; Stderr = "" }
                | _ -> failwith "Unexpected firewalld guard fixture command."
            let environment: HostEnvironment =
                { Root = root; Run = run; UtcNow = fun () -> DateTimeOffset.UnixEpoch }
            let configuration =
                { FirewalldModel.empty "settings" "DefaultZone" with SettingValue = Some "isolated" }
            Assert.Throws<FirewalldGuardNative.BackendError>(TestDelegate(fun () ->
                FirewalldGuardNative.guardMutation environment configuration (Some "DefaultZone=isolated\n"))) |> ignore
        finally
            Environment.SetEnvironmentVariable("SSH_CONNECTION", previous)
            if Directory.Exists root then Directory.Delete(root, true)
