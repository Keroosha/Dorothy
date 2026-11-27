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
    let validateContext context defaultZone zones policies ipsets serviceDefinitions =
        FirewalldGuardNative.validateSshGuardWithDefinitions
            context defaultZone zones policies ipsets serviceDefinitions
    let validate zones policies ipsets serviceDefinitions =
        validateContext context "public" zones policies ipsets serviceDefinitions
    let expectDenied action =
        Assert.Throws<FirewalldGuardNative.BackendError>(TestDelegate action) |> ignore

    [<Test>]
    member _.``A shared inbound service can change unrelated ports but an output consumer can see the client port``() =
        let defs output =
            let policy = if output then Map.ofList ["out", "<policy><ingress-zone name='HOST'/><egress-zone name='ANY'/><service name='parent'/></policy>"] else Map.empty
            Map.ofList ["policy", policy; "zone", Map.ofList ["work", "<zone><service name='parent'/></zone>"]
                        "service", Map.ofList ["parent", "<service><include service='app'/></service>"]]
        let port n = Some(sprintf "<service><port protocol='tcp' port='%d'/></service>" n)
        let safe consumers oldPort newPort =
            FirewalldReferences.preservesManagement FirewalldGuardNative.parseXml "service" "app" (defs consumers) (Some 2222) (port oldPort) (port newPort)
        Assert.That(safe false 8080 8081, Is.True)
        Assert.That(safe false 2222 8081, Is.False)
        Assert.That(safe true 8080 8081, Is.False)

    [<Test>]
    member _.``Guard matches peer and local ports and proves disjoint family and source port``() =
        let drop sourcePort family address =
            sprintf "<rule family=\"%s\"><source address=\"%s\"/><source-port port=\"%s\" protocol=\"tcp\"/><port port=\"22\" protocol=\"tcp\"/><drop/></rule>" family address sourcePort
        let zone rule = "<zone><interface name=\"eth0\"/><service name=\"ssh\"/>" + rule + "</zone>"
        expectDenied (fun () -> validate (Map.ofList [ "public", zone (drop "49201" "ipv4" "192.0.2.0/24") ]) Map.empty Map.empty services)
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
        expectDenied (fun () -> validate (Map.ofList [ "public", safeZone; "unrelated", "<zone target=\"DROP\"><interface name=\"en+\"/></zone>" ]) Map.empty Map.empty services)
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
        validate terminalZone (Map.ofList [ "positive-host", positiveAllow ]) Map.empty services

        let explicitServiceZone = Map.ofList [ "public", safeZone ]
        let positiveDrop =
            "<policy target=\"DROP\" priority=\"10\"><ingress-zone name=\"public\"/><egress-zone name=\"HOST\"/></policy>"
        validate explicitServiceZone (Map.ofList [ "drop-after-service", positiveDrop ]) Map.empty services

        let terminalAccept = Map.ofList [ "public", "<zone target=\"ACCEPT\"/>" ]
        expectDenied (fun () -> validate terminalAccept (Map.ofList [ "drop-before-target", positiveDrop ]) Map.empty services)
        let hostEgressDrop = "<policy target=\"DROP\" priority=\"-1\"><ingress-zone name=\"HOST\"/><egress-zone name=\"public\"/></policy>"
        validate (Map.ofList [ "public", safeZone ]) (Map.ofList [ "host-egress-drop", hostEgressDrop ]) Map.empty services

        let transitAccept =
            "<policy target=\"ACCEPT\" priority=\"-1\"><ingress-zone name=\"public\"/><egress-zone name=\"ANY\"/><port port=\"22\" protocol=\"tcp\"/></policy>"
        expectDenied (fun () -> validate terminalZone (Map.ofList [ "transit", transitAccept ]) Map.empty services)

        let unrelated =
            "<policy target=\"CONTINUE\" priority=\"-1\"><ingress-zone name=\"ANY\"/><egress-zone name=\"HOST\"/><rule family=\"ipv4\"><destination address=\"198.51.100.0/24\"/><port port=\"22\" protocol=\"tcp\"/><drop/></rule></policy>"
        validate (Map.ofList [ "public", safeZone ]) (Map.ofList [ "unrelated", unrelated ]) Map.empty services
 

        let otherEgress =
            "<policy target=\"DROP\"><ingress-zone name=\"public\"/><egress-zone name=\"docker\"/></policy>"
        validate (Map.ofList [ "public", safeZone; "docker", "<zone/>" ]) (Map.ofList [ "docker-only", otherEgress ]) Map.empty services

        let replyRule destinationPort =
            sprintf
                "<policy target=\"CONTINUE\" priority=\"-1\"><ingress-zone name=\"HOST\"/><egress-zone name=\"public\"/><rule family=\"ipv4\"><source address=\"192.0.2.2\"/><source-port port=\"22\" protocol=\"tcp\"/><destination address=\"192.0.2.1\"/><port port=\"%s\" protocol=\"tcp\"/><drop/></rule></policy>"
                destinationPort
        validate (Map.ofList [ "public", safeZone ]) (Map.ofList [ "reply-block", replyRule "49200" ]) Map.empty services
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
    member _.``Protocol-only TCP services authorize stable SSH and UDP remains disjoint``() =
        let protocolOnly = Map.ofList [ "ssh", "<service><protocol value=\"tcp\"/></service>" ]
        let zoneWithSsh = Map.ofList [ "public", "<zone><interface name=\"eth0\"/><service name=\"ssh\"/></zone>" ]
        validate zoneWithSsh Map.empty Map.empty protocolOnly
        let legacyProtocolOnly = Map.ofList [ "ssh", "<service><port port=\"\" protocol=\"tcp\"/></service>" ]
        validate zoneWithSsh Map.empty Map.empty legacyProtocolOnly

        let tcpDrop = "<rule family=\"ipv4\"><service name=\"ssh\"/><drop/></rule>"
        expectDenied (fun () -> validate (Map.ofList [ "public", "<zone><interface name=\"eth0\"/>" + tcpDrop + "</zone>" ]) Map.empty Map.empty protocolOnly)

        let udpService = Map.add "udp-only" "<service><protocol value=\"udp\"/></service>" services
        let disjointRule = "<rule family=\"ipv4\"><service name=\"udp-only\"/><drop/></rule>"
        validate (Map.ofList [ "public", "<zone><interface name=\"eth0\"/><service name=\"ssh\"/>" + disjointRule + "</zone>" ]) Map.empty Map.empty udpService

    [<Test>]
    member _.``Effective runtime policies, live services and retained ipsets are checked``() =
        let root = Path.Combine(Path.GetTempPath(), "dorothy-firewalld-runtime-guard-" + Guid.NewGuid().ToString("N"))
        let previous = Environment.GetEnvironmentVariable "SSH_CONNECTION"
        let runtimeZone =
            "public\n  target: default\n  ingress-priority: 0\n  egress-priority: 0\n  icmp-block-inversion: no\n  interfaces:\n  sources:\n  services: ssh\n  ports:\n  protocols:\n  forward: no\n  masquerade: no\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n"
        let runtimeSourceZone =
            "source-net\n  target: default\n  ingress-priority: 0\n  egress-priority: 0\n  icmp-block-inversion: no\n  interfaces:\n  sources: 192.0.2.0/24\n  services: ssh\n  ports:\n  protocols:\n  forward: no\n  masquerade: no\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n"
        let safeRuntimePolicy =
            "runtime-block\n  priority: -1\n  target: CONTINUE\n  ingress-zones: ANY\n  egress-zones: HOST\n  services:\n  ports:\n  protocols:\n  masquerade: no\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n\t\trule family=\"ipv4\" source NOT address=\"192.0.2.0/24\" drop\n"
        let mutable runtimePolicy =
            "runtime-block\n  priority: -1\n  target: DROP\n  ingress-zones: ANY\n  egress-zones: HOST\n  services:\n  ports:\n  protocols:\n  masquerade: no\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n"
        let serviceInfo name ports =
            String.concat "\n"
                [ name; "  ports: " + ports; "  protocols:"; "  source-ports:"; "  modules:"
                  "  destination:"; "  includes:"; "  helpers:" ]
        try
            for directory in [ "etc/firewalld"; "usr/lib/firewalld/zones"; "usr/lib/firewalld/services"; "usr/lib/firewalld/ipsets"; "run/lock" ] do
                Directory.CreateDirectory(Path.Combine(root, directory)) |> ignore
            File.WriteAllText(Path.Combine(root, "etc/firewalld/firewalld.conf"), "DefaultZone=public\nFlushAllOnReload=no\n")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/public.xml"), "<zone><service name=\"ssh\"/></zone>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/source-net.xml"), "<zone><source address=\"192.0.2.0/24\"/><service name=\"ssh\"/></zone>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/offroute.xml"), "<zone target=\"DROP\"><interface name=\"wg+\"/></zone>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/services/ssh.xml"), sshService)
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/offline-loopback.xml"), "<zone target=\"DROP\" ingress-priority=\"-10\"><interface name=\"lo\"/></zone>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/zones/offline-down.xml"), "<zone target=\"DROP\" ingress-priority=\"-10\"><interface name=\"eth9\"/></zone>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/services/_internal.xml"), "<service><port port=\"8080\" protocol=\"tcp\"/></service>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/services/stale-svc.xml"), "<service><port port=\"8080\" protocol=\"tcp\"/></service>")
            File.WriteAllText(Path.Combine(root, "usr/lib/firewalld/ipsets/management-peers.xml"), "<ipset type=\"hash:net\"><option name=\"family\" value=\"inet\"/></ipset>")
            Environment.SetEnvironmentVariable("SSH_CONNECTION", "192.0.2.1 49200 192.0.2.2 22")
            let run executable arguments _ : CommandResult =
                match executable, arguments with
                | "ip", [ "-j"; "link"; "show" ] ->
                    { ExitCode = 0; Stdout = "[{\"ifname\":\"lo\",\"link_type\":\"loopback\",\"operstate\":\"UNKNOWN\",\"flags\":[\"LOOPBACK\",\"UP\"]},{\"ifname\":\"eth0\",\"link_type\":\"ether\",\"operstate\":\"UP\",\"flags\":[\"BROADCAST\",\"UP\"]},{\"ifname\":\"eth9\",\"link_type\":\"ether\",\"operstate\":\"DOWN\",\"flags\":[\"BROADCAST\"]}]"; Stderr = "" }
                | "ip", _ -> { ExitCode = 0; Stdout = "[{\"dev\":\"eth0\"}]"; Stderr = "" }
                | "firewall-cmd", [ "--get-default-zone" ] -> { ExitCode = 0; Stdout = "public"; Stderr = "" }
                | "firewall-cmd", [ "--get-zone-of-interface=eth0" ] -> { ExitCode = 2; Stdout = "no zone"; Stderr = "" }
                | "firewall-cmd", [ "--get-zones" ] -> { ExitCode = 0; Stdout = "public source-net"; Stderr = "" }
                | "firewall-cmd", [ "--get-policies" ] -> { ExitCode = 0; Stdout = "runtime-block"; Stderr = "" }
                | "firewall-cmd", [ "--get-ipsets" ] -> { ExitCode = 0; Stdout = "management-peers"; Stderr = "" }
                | "firewall-cmd", [ "--info-ipset=management-peers" ] ->
                    { ExitCode = 0
                      Stdout = "management-peers\n  type: hash:net\n  options: family=inet\n  entries: 192.0.2.0/24\n"
                      Stderr = "" }
                | "firewall-cmd", [ "--info-service=ssh" ] -> { ExitCode = 0; Stdout = serviceInfo "ssh" "22/tcp"; Stderr = "" }
                | "firewall-cmd", [ "--info-service=stale-svc" ] -> { ExitCode = 0; Stdout = serviceInfo "stale-svc" "22/tcp"; Stderr = "" }
                | "firewall-cmd", [ ("--zone=public" | "--zone=source-net"); "--list-interfaces" ] ->
                    { ExitCode = 0; Stdout = ""; Stderr = "" }
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

            runtimePolicy <- safeRuntimePolicy
            Assert.DoesNotThrow(TestDelegate(fun () ->
                FirewalldGuardNative.guardMutation environment configuration (Some "DefaultZone=public\nLogDenied=all\n")))

            runtimePolicy <-
                "runtime-block\n  priority: -1\n  target: CONTINUE\n  ingress-zones: ANY\n  egress-zones: HOST\n  services:\n  ports:\n  protocols:\n  masquerade: no\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n\t\trule family=\"ipv4\" service name=\"stale-svc\" drop\n"
            Assert.Throws<FirewalldGuardNative.BackendError>(TestDelegate(fun () ->
                FirewalldGuardNative.guardMutation environment configuration (Some "DefaultZone=public\nLogDenied=all\n"))) |> ignore

            runtimePolicy <- safeRuntimePolicy
            let candidatePolicy =
                "<policy target=\"CONTINUE\" priority=\"-1\"><ingress-zone name=\"source-net\"/><egress-zone name=\"HOST\"/><rule family=\"ipv4\"><source ipset=\"management-peers\"/><port port=\"22\" protocol=\"tcp\"/><drop/></rule></policy>"
            let policyConfiguration = FirewalldModel.empty "policy" "candidate-block"
            Assert.Throws<FirewalldGuardNative.BackendError>(TestDelegate(fun () ->
                FirewalldGuardNative.guardMutation environment policyConfiguration (Some candidatePolicy))) |> ignore
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

    [<Test>]
    member _.``PREROUTING zone-to-ANY policies inspect positive-priority DNAT and marks``() =
        let zone = Map.ofList [ "public", safeZone ]
        let plain =
            "<policy target=\"CONTINUE\" priority=\"10\"><ingress-zone name=\"public\"/><egress-zone name=\"ANY\"/><forward-port port=\"22\" protocol=\"tcp\" to-addr=\"198.51.100.8\"/></policy>"
        let richDnat =
            "<policy target=\"CONTINUE\" priority=\"10\"><ingress-zone name=\"public\"/><egress-zone name=\"ANY\"/><rule family=\"ipv4\"><forward-port port=\"22\" protocol=\"tcp\" to-addr=\"198.51.100.8\"/></rule></policy>"
        let richMark =
            "<policy target=\"CONTINUE\" priority=\"10\"><ingress-zone name=\"public\"/><egress-zone name=\"ANY\"/><rule family=\"ipv4\"><port port=\"22\" protocol=\"tcp\"/><mark set=\"0x1\"/></rule></policy>"
        for policy in [ plain; richDnat; richMark ] do
            expectDenied (fun () -> validate zone (Map.ofList [ "nat", policy ]) Map.empty services)

        let unrelatedPort = plain.Replace("port=\"22\"", "port=\"2222\"", StringComparison.Ordinal)
        validate zone (Map.ofList [ "nat", unrelatedPort ]) Map.empty services
        let unrelatedTransitDrop =
            "<policy target=\"DROP\" priority=\"-1\"><ingress-zone name=\"public\"/><egress-zone name=\"ANY\"/><port port=\"2222\" protocol=\"tcp\"/></policy>"
        validate zone (Map.ofList [ "transit-drop", unrelatedTransitDrop ]) Map.empty services

        let hostDestination = "<zone><source address=\"192.0.2.2\"/></zone>"
        let concreteEgressDnat =
            "<policy target=\"CONTINUE\" priority=\"10\"><ingress-zone name=\"public\"/><egress-zone name=\"host-address\"/><forward-port port=\"22\" protocol=\"tcp\" to-addr=\"198.51.100.8\"/></policy>"
        expectDenied (fun () ->
            validate
                (Map.ofList [ "public", safeZone; "host-address", hostDestination ])
                (Map.ofList [ "concrete-nat", concreteEgressDnat ])
                Map.empty services)

        let anyToHostDnat =
            "<policy target=\"CONTINUE\" priority=\"10\"><ingress-zone name=\"ANY\"/><egress-zone name=\"HOST\"/><forward-port port=\"22\" protocol=\"tcp\" to-addr=\"198.51.100.8\"/></policy>"
        expectDenied (fun () -> validate zone (Map.ofList [ "any-host-nat", anyToHostDnat ]) Map.empty services)
        let concreteHost = anyToHostDnat.Replace("ingress-zone name=\"ANY\"", "ingress-zone name=\"public\"")
        expectDenied (fun () -> validate zone (Map.ofList [ "host-nat", concreteHost ]) Map.empty services)

    [<Test>]
    member _.``Zone prerouting marks precede grants and an earlier terminal HOST grant wins``() =
        let withMark port =
            Map.ofList [ "public", "<zone><service name=\"ssh\"/><rule family=\"ipv4\"><port port=\"" + port + "\" protocol=\"tcp\"/><mark set=\"0x2\"/></rule></zone>" ]
        expectDenied (fun () -> validate (withMark "22") Map.empty Map.empty services)
        validate (withMark "2222") Map.empty Map.empty services
        let host target priority =
            sprintf "<policy target=\"%s\" priority=\"%d\"><ingress-zone name=\"public\"/><egress-zone name=\"HOST\"/></policy>" target priority
        validate (Map.ofList [ "public", "<zone target=\"DROP\"/>" ])
            (Map.ofList [ "early", host "ACCEPT" -50; "late", host "DROP" -10 ]) Map.empty services

    [<Test>]
    member _.``Both NDP types must survive protocol-wide denies on next-hop zones``() =
        let v6 = FirewalldGuardNative.parseSshContext "2001:db8:1::10 49200 2001:db8:2::20 22" "[{\"dev\":\"eth0\",\"gateway\":\"fe80::1\"}]"
        let zones = Map.ofList [ "public", safeZone; "peer", "<zone><source address=\"2001:db8:1::/64\"/><service name=\"ssh\"/></zone>"
                                 "next-hop", "<zone><source address=\"fe80::/10\"/></zone>" ]
        let policy rules priority target =
            sprintf "<policy priority=\"%d\" target=\"%s\"><ingress-zone name=\"next-hop\"/><egress-zone name=\"HOST\"/>%s</policy>" priority target rules
        let ns = "<rule family=\"ipv6\"><icmp-type name=\"neighbour-solicitation\"/><accept/></rule>"
        let na = "<rule family=\"ipv6\"><icmp-type name=\"neighbour-advertisement\"/><accept/></rule>"
        let deny = "<rule family=\"ipv6\"><protocol value=\"ipv6-icmp\"/><drop/></rule>"
        let check permits = validateContext v6 "public" zones (Map.ofList [ "early", policy permits -100 "CONTINUE"; "late", policy deny -50 "CONTINUE" ]) Map.empty services
        expectDenied (fun () -> check ns)
        check (ns + na)


    [<Test>]
    member _.``A parent service destination does not hide its included SSH service``() =
        let definitions =
            Map.ofList
                [ "ssh", sshService
                  "ssh-base", "<service><port port=\"22\" protocol=\"tcp\"/></service>"
                  "wrapper", "<service><destination ipv4=\"198.51.100.8\"/><include service=\"ssh-base\"/></service>" ]
        let rule = "<rule family=\"ipv4\"><service name=\"wrapper\"/><drop/></rule>"
        let zone = "<zone><interface name=\"eth0\"/><service name=\"ssh\"/>" + rule + "</zone>"
        expectDenied (fun () -> validate (Map.ofList [ "public", zone ]) Map.empty Map.empty definitions)

    [<Test>]
    member _.``Only matching stable SSH grants survive source-port uncertainty``() =
        let onlyEphemeralPort =
            "<zone target=\"DROP\"><interface name=\"eth0\"/><source-port port=\"49200\" protocol=\"tcp\"/></zone>"
        expectDenied (fun () -> validate (Map.ofList [ "public", onlyEphemeralPort ]) Map.empty Map.empty Map.empty)

        let safeSource = "<zone><source address=\"192.0.2.0/24\"/><service name=\"ssh\"/></zone>"
        let interfaceDrop = "<zone target=\"DROP\"><interface name=\"eth0\"/></zone>"
        validate
            (Map.ofList [ "public", interfaceDrop; "management", safeSource ])
            Map.empty Map.empty services

    [<Test>]
    member _.``Source precedence and zone priorities scope uncertain ingress bindings``() =
        let management =
            "<zone ingress-priority=\"0\"><source address=\"192.0.2.0/24\"/><service name=\"ssh\"/></zone>"
        let higherPriorityNumberMac =
            "<zone target=\"DROP\" ingress-priority=\"10\"><source mac=\"02:00:00:00:00:01\"/></zone>"
        validate
            (Map.ofList [ "public", "<zone target=\"ACCEPT\"><interface name=\"eth0\"/></zone>"
                          "management", management; "mac", higherPriorityNumberMac ])
            Map.empty Map.empty services

        let lowerPriorityMac =
            "<zone target=\"DROP\" ingress-priority=\"-1\"><source mac=\"02:00:00:00:00:01\"/></zone>"
        expectDenied (fun () ->
            validate
                (Map.ofList [ "public", "<zone target=\"ACCEPT\"><interface name=\"eth0\"/></zone>"
                              "management", management; "mac", lowerPriorityMac ])
                Map.empty Map.empty services)

        let priorities =
            Map.ofList
                [ "public", "<zone target=\"ACCEPT\"><interface name=\"eth0\"/></zone>"
                  "first", "<zone ingress-priority=\"-10\"><interface name=\"eth0\"/><service name=\"ssh\"/></zone>"
                  "later", "<zone target=\"DROP\" ingress-priority=\"10\"><interface name=\"eth0\"/></zone>" ]
        validate priorities Map.empty Map.empty services
        let sourceSafe =
            "<zone ingress-priority=\"0\"><source address=\"192.0.2.0/24\"/><service name=\"ssh\"/></zone>"
        let earlierInterface =
            "<zone target=\"DROP\" ingress-priority=\"-10\"><interface name=\"eth0\"/></zone>"
        expectDenied (fun () ->
            validate
                (Map.ofList [ "public", safeZone; "management", sourceSafe; "earlier-interface", earlierInterface ])
                Map.empty Map.empty services)
        let tiedInterface =
            "<zone target=\"DROP\" ingress-priority=\"0\"><interface name=\"eth0\"/></zone>"
        validate
            (Map.ofList [ "public", safeZone; "management", sourceSafe; "tied-interface", tiedInterface ])
            Map.empty Map.empty services

        let asymmetric =
            Map.ofList
                [ "public", safeZone
                  "other", "<zone target=\"DROP\"><interface name=\"eth1\"/></zone>" ]
        expectDenied (fun () -> validate asymmetric Map.empty Map.empty services)

    [<Test>]
    member _.``ICMP blocks and opposite-family plain DNAT are disjoint except for IPv6 NDP``() =
        let ipv4Echo =
            "<zone><interface name=\"eth0\"/><service name=\"ssh\"/><icmp-block name=\"echo-request\"/></zone>"
        validate (Map.ofList [ "public", ipv4Echo ]) Map.empty Map.empty services
        let richEcho =
            "<rule family=\"ipv4\"><icmp-type name=\"echo-request\"/><drop/></rule>"
        validate (Map.ofList [ "public", "<zone><interface name=\"eth0\"/><service name=\"ssh\"/>" + richEcho + "</zone>" ]) Map.empty Map.empty services

        let ipv6 = FirewalldGuardNative.parseSshContext "2001:db8::1 49200 2001:db8::2 22" "[{\"dev\":\"eth0\"}]"
        let ipv6Echo =
            "<zone><interface name=\"eth0\"/><service name=\"ssh\"/><icmp-block name=\"echo-request\"/></zone>"
        validateContext ipv6 "public" (Map.ofList [ "public", ipv6Echo ]) Map.empty Map.empty services
        let ipv6Ndp =
            "<zone><interface name=\"eth0\"/><service name=\"ssh\"/><icmp-block name=\"neighbour-solicitation\"/></zone>"
        expectDenied (fun () -> validateContext ipv6 "public" (Map.ofList [ "public", ipv6Ndp ]) Map.empty Map.empty services)
        let ipv6NdpRule =
            "<rule family=\"ipv6\"><icmp-type name=\"neighbour-advertisement\"/><drop/></rule>"
        expectDenied (fun () ->
            validateContext ipv6 "public"
                (Map.ofList [ "public", "<zone><interface name=\"eth0\"/><service name=\"ssh\"/>" + ipv6NdpRule + "</zone>" ])
                Map.empty Map.empty services)

        let oppositeFamilyDnat =
            "<zone><interface name=\"eth0\"/><service name=\"ssh\"/><forward-port port=\"22\" protocol=\"tcp\" to-addr=\"2001:db8::8\"/></zone>"
        validate (Map.ofList [ "public", oppositeFamilyDnat ]) Map.empty Map.empty services

    [<Test>]
    member _.``Dotted netmasks, limited accepts and MSS clamp preserve explicit SSH``() =
        let drop address =
            "<rule family=\"ipv4\"><source address=\"" + address + "\"/><drop/></rule>"
        let zone rule = "<zone><interface name=\"eth0\"/><service name=\"ssh\"/>" + rule + "</zone>"
        expectDenied (fun () ->
            validate (Map.ofList [ "public", zone (drop "192.0.2.0/255.255.255.0") ]) Map.empty Map.empty services)
        validate (Map.ofList [ "public", zone (drop "198.51.100.0/255.255.255.0") ]) Map.empty Map.empty services

        let limitedAccept =
            "<rule family=\"ipv4\"><port port=\"22\" protocol=\"tcp\"/><accept><limit value=\"1/m\"/></accept></rule>"
        validate (Map.ofList [ "public", zone limitedAccept ]) Map.empty Map.empty services
        expectDenied (fun () ->
            validate
                (Map.ofList [ "public", "<zone target=\"DROP\"><interface name=\"eth0\"/>" + limitedAccept + "</zone>" ])
                Map.empty Map.empty services)

        let clamp = "<rule family=\"ipv4\"><tcp-mss-clamp/></rule>"
        validate (Map.ofList [ "public", zone clamp ]) Map.empty Map.empty services
        let pmtuClamp = "<rule family=\"ipv4\"><port port=\"22\" protocol=\"tcp\"/><tcp-mss-clamp value=\"pmtu\"/></rule>"
        let numericClamp = "<rule family=\"ipv4\"><port port=\"22\" protocol=\"tcp\"/><tcp-mss-clamp value=\"1400\"/></rule>"
        validate (Map.ofList [ "public", zone pmtuClamp ]) Map.empty Map.empty services
        validate (Map.ofList [ "public", zone numericClamp ]) Map.empty Map.empty services
        let unknownSelectorAccept =
            "<rule family=\"ipv4\"><source mac=\"02:00:00:00:00:01\"/><accept/></rule>"
        validate (Map.ofList [ "public", zone unknownSelectorAccept ]) Map.empty Map.empty services
        let masqueradeRule =
            "<rule family=\"ipv4\"><port port=\"22\" protocol=\"tcp\"/><masquerade/></rule>"
        validate (Map.ofList [ "public", zone masqueradeRule ]) Map.empty Map.empty services
    [<Test>]
    member _.``IPv6 neighbor discovery is checked through the reply egress zone``() =
        let ipv6 = FirewalldGuardNative.parseSshContext "2001:db8::1 49200 2001:db8::2 22" "[{\"dev\":\"eth0\"}]"
        let peerZone = "<zone><source address=\"2001:db8::1\"/><service name=\"ssh\"/></zone>"
        let outputNdpDrop =
            "<policy target=\"CONTINUE\" priority=\"-1\"><ingress-zone name=\"HOST\"/><egress-zone name=\"peer\"/><rule family=\"ipv6\"><icmp-type name=\"neighbour-solicitation\"/><drop/></rule></policy>"
        expectDenied (fun () ->
            validateContext ipv6 "public"
                (Map.ofList [ "public", safeZone; "peer", peerZone ])
                (Map.ofList [ "host-to-peer", outputNdpDrop ])
                Map.empty services)
