namespace Dorothy.Tests

open System
open NUnit.Framework

module Model = Dorothy.DSL.FirewalldModel

module private FirewalldCatalogue =
    let element name attrs text children : Model.Element =
        { Name = name; Attributes = Map.ofList attrs; Text = text; Children = children }
    let leaf name attrs = element name attrs None []
    let text name value = element name [] (Some value) []
    let nested name attrs children = element name attrs None children
    let render config =
        config |> Model.toJson |> Dorothy.HostHelper.FirewalldModel.parse |> Dorothy.HostHelper.Firewalld.render
    let assertNative (config: Model.Configuration) expected =
        let canonical = Dorothy.HostHelper.Firewalld.canonicalXml config.Kind
        Assert.That(canonical (render config), Is.EqualTo(canonical expected), config.Kind + "/" + config.Name)

open FirewalldCatalogue

[<TestFixture>]
type FirewalldCatalogueTests() =
    // The expected XML uses the 2.3.1 IO parsers' public vocabulary, independent of the serializer.
    [<Test>]
    member _.``Definition wire round trip preserves native filtering and descriptive values``() =
        let version = Map.ofList [ "version", "2" ]
        let objects =
            [ { Model.empty "service" "example-api" with
                  Attributes = version; Ports = [ "8440-8443/tcp" ]; Protocols = [ "esp" ]
                  Elements = [ text "short" "Example & API"; text "description" "Internal listener"
                               leaf "source-port" [ "port", "4100-4110"; "protocol", "udp" ]; leaf "include" [ "service", "https" ]
                               leaf "helper" [ "name", "ftp" ]; leaf "module" [ "name", "nf_conntrack_ftp" ]
                               leaf "destination" [ "ipv4", "192.0.2.0/24"; "ipv6", "2001:db8::/64" ] ] },
              """<service version="2"><short>Example &amp; API</short><description>Internal listener</description><port port="8440-8443" protocol="tcp"/><protocol value="esp"/><source-port port="4100-4110" protocol="udp"/><include service="https"/><helper name="ftp"/><module name="nf_conntrack_ftp"/><destination ipv4="192.0.2.0/24" ipv6="2001:db8::/64"/></service>"""
              { Model.empty "ipset" "example-set" with
                  Attributes = Map.ofList [ "type", "hash:net" ]; Elements = [ leaf "option" [ "name", "family"; "value", "inet6" ]; text "entry" "2001:db8:1::/64" ] },
              """<ipset type="hash:net"><option name="family" value="inet6"/><entry>2001:db8:1::/64</entry></ipset>"""
              { Model.empty "helper" "example-ftp" with
                  Attributes = Map.ofList [ "module", "nf_conntrack_ftp"; "family", "ipv4" ]; Ports = [ "2121/tcp" ] },
              """<helper module="nf_conntrack_ftp" family="ipv4"><port port="2121" protocol="tcp"/></helper>"""
              { Model.empty "icmptype" "echo-request" with Elements = [ leaf "destination" [ "ipv6", "yes" ] ] },
              """<icmptype><destination ipv6="yes"/></icmptype>""" ]
        for config, expected in objects do assertNative config expected

    [<Test>]
    member _.``A source bound policy can permit host ingress without enabling NAT or transit``() =
        let deny = nested "rule" [ "family", "ipv6"; "priority", "-10" ] [
            leaf "source" [ "ipset", "denied" ]; leaf "port" [ "port", "8443"; "protocol", "tcp" ]
            nested "log" [ "prefix", "example: "; "level", "notice" ] [ leaf "limit" [ "value", "2/m"; "burst", "3" ] ]
            leaf "drop" [] ]
        let config =
            { Model.empty "policy" "allow-api" with
                Ingress = [ "clients" ]; Egress = [ "HOST" ]; Priority = -2
                Services = [ "example-api" ]; Elements = [ deny ] }
        assertNative config """<policy target="CONTINUE" priority="-2"><ingress-zone name="clients"/><egress-zone name="HOST"/><service name="example-api"/><rule family="ipv6" priority="-10"><source ipset="denied"/><port port="8443" protocol="tcp"/><log prefix="example: " level="notice"><limit value="2/m" burst="3"/></log><drop/></rule></policy>"""
        Assert.That(Model.references config, Is.EquivalentTo [ "zone", "clients"; "service", "example-api"; "ipset", "denied" ])

    [<Test>]
    member _.``Unrecognized native elements or attributes cannot become privileged host configuration``() =
        for candidate in [ leaf "direct" [ "chain", "INPUT" ]; leaf "forward-port" [ "port", "443"; "protocol", "tcp" ];
                           nested "rule" [] [ leaf "drop" [ "unexpected", "value" ] ]; leaf "source" [ "address", "192.0.2.1"; "ipset", "conflict" ] ] do
            let config = { Model.empty "zone" "clients" with Elements = [ candidate ] }
            Assert.Throws<ArgumentException>(fun () -> Model.toJson config |> ignore) |> ignore

    [<Test>]
    member _.``Daemon catalogue keeps independently owned keys and rejects cross-key values``() =
        // firewalld 2.3.1 firewalld_conf.valid_keys; StrictForwardPorts uses the original owner.
        let scenarios =
            [ "DefaultZone", "clients"; "MinimalMark", "101"; "CleanupOnExit", "yes"
              "CleanupModulesOnExit", "no"; "IPv6_rpfilter", "strict-forward"; "IndividualCalls", "no"
              "LogDenied", "unicast"; "AutomaticHelpers", "system"; "FirewallBackend", "nftables"
              "FlushAllOnReload", "yes"; "ReloadPolicy", "INPUT:DROP,FORWARD:REJECT,OUTPUT:ACCEPT"
              "RFC3964_IPv4", "yes"; "AllowZoneDrifting", "no"; "NftablesFlowtable", "eth1 eth2"
              "NftablesCounters", "yes"; "NftablesTableOwner", "yes"; "Lockdown", "no" ]
        let firewall = Dorothy.DSL.Firewalld.firewalld {
            yield! scenarios |> List.map (fun (key, value) -> Dorothy.DSL.Firewalld.setting key value)
            Dorothy.DSL.Firewalld.strictForwardPorts true
        }
        let actual =
            firewall.Objects |> List.map (fun spec ->
                let c = Model.parse spec.Configuration
                Model.settingKey c, c.SettingValue.Value)
        Assert.That(actual, Is.EquivalentTo scenarios)
        Assert.That(firewall.StrictForwardPorts, Is.EqualTo(Some true))
        for key, value in [ "StrictForwardPorts", "yes"; "ReloadPolicy", "unicast"; "DefaultZone", "../zones"; "LogDenied", "all\nDefaultZone=trusted" ] do
            Assert.Throws<ArgumentException>(fun () -> Dorothy.DSL.Firewalld.setting key value |> ignore) |> ignore
