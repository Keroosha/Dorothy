namespace Dorothy.Tests

module internal FirewalldPublicCatalogueConsumer =
    open Dorothy.DSL
    open Dorothy.DSL.Firewalld

    let private commonIpSetOptions =
        [ "family", "inet"; "hashsize", "1024"; "maxelem", "64" ]

    let private ipsetWith name typeName values options =
        ipset name {
            short "Catalogue set"
            Defined.description "A named native ipset"
            version "1"
            ipsetType typeName
            ipsetOptions options
            entries values
        }

    let private ipsets =
        [ ipsetWith "catalogue-ip-set" "hash:ip" [ "192.0.2.10" ] commonIpSetOptions
          ipsetWith "catalogue-ip-port" "hash:ip,port" [ "192.0.2.10,tcp:80" ] commonIpSetOptions
          ipsetWith "catalogue-ip-port-ip" "hash:ip,port,ip" [ "192.0.2.10,tcp:80,192.0.2.11" ] commonIpSetOptions
          ipsetWith "catalogue-ip-port-net" "hash:ip,port,net" [ "192.0.2.10,tcp:80,198.51.100.0/24" ] commonIpSetOptions
          ipsetWith "catalogue-ip-mark" "hash:ip,mark" [ "192.0.2.10,0x1" ] commonIpSetOptions
          ipsetWith "catalogue-net" "hash:net" [ "192.0.2.0/24" ] commonIpSetOptions
          ipsetWith "catalogue-net-net" "hash:net,net" [ "192.0.2.0/24,198.51.100.0/24" ] commonIpSetOptions
          ipsetWith "catalogue-net-port" "hash:net,port" [ "192.0.2.0/24,tcp:80" ] commonIpSetOptions
          ipsetWith "catalogue-net-port-net" "hash:net,port,net" [ "192.0.2.0/24,tcp:80,198.51.100.0/24" ] commonIpSetOptions
          ipsetWith "catalogue-net-iface" "hash:net,iface" [ "192.0.2.0/24,eth0" ] commonIpSetOptions
          ipsetWith "catalogue-mac" "hash:mac" [ "02:00:00:00:00:01" ] [ "hashsize", "1024"; "maxelem", "64" ]
          ipsetWith "catalogue-timeout" "hash:ip" [] [ "family", "inet"; "timeout", "30"; "hashsize", "1024"; "maxelem", "64" ] ]

    let private settings =
        [ "DefaultZone", "catalogue-edge"
          "LogDenied", "unicast"
          "MinimalMark", "101"
          "CleanupOnExit", "yes"
          "CleanupModulesOnExit", "no"
          "IPv6_rpfilter", "strict-forward"
          "IndividualCalls", "no"
          "AutomaticHelpers", "system"
          "FirewallBackend", "nftables"
          "FlushAllOnReload", "yes"
          "ReloadPolicy", "INPUT:DROP,FORWARD:REJECT,OUTPUT:ACCEPT"
          "RFC3964_IPv4", "yes"
          "AllowZoneDrifting", "no"
          "NftablesFlowtable", "eth1 eth2"
          "NftablesCounters", "yes"
          "NftablesTableOwner", "yes"
          "Lockdown", "no" ]

    let specification =
        firewalld {
            zone "catalogue-edge" {
                target FirewalldTarget.Drop
                interfaces [ "eth0" ]
                services [ "catalogue-service" ]
                transportPorts [ tcpPortRange 8000 8010; udpPort 53 ]
                protocols [ "gre" ]
                masquerade true
                forward true
                Zone.ingressPriority -20
                Zone.egressPriority 15
                sources [ sourceIPSet "catalogue-ip-set"; sourceAddress "192.0.2.0/24" ]
                sourcePorts [ tcpPortRange 1000 1002 ]
                forwardPort (tcpPort 8443) (Some "198.51.100.10") (Some (tcpPort 443))
                icmpBlocks [ "echo-request" ]
                icmpBlockInversion
                short "Catalogue edge"
                Defined.description "Firewalld native catalogue coverage"
                version "1"
                richRules
                    [ richRule {
                          family FirewalldFamily.IPv4
                          richPriority -20
                          sourceAddress "192.0.2.0/24"
                          invertDestination (destinationAddress "198.51.100.10")
                          richService "catalogue-base"
                          RichRule.log (Some "notice") (Some "catalogue: ")
                          RichRule.limitBurst 10 FirewalldLimitUnit.Minute 3
                          RichRule.accept
                      }
                      richRule {
                          family FirewalldFamily.IPv4
                          richPriority -10
                          invertSource (sourceIPSet "catalogue-ip-set")
                          invertDestination (destinationIPSet "catalogue-ip-set")
                          richPort (tcpPort 8080)
                          RichRule.drop
                      }
                      richRule {
                          family FirewalldFamily.IPv4
                          sourceMac "02:00:00:00:00:02"
                          richProtocol "gre"
                          RichRule.rejectWith "icmp-admin-prohibited"
                      }
                      richRule {
                          family FirewalldFamily.IPv6
                          richIcmpType "echo-request"
                          RichRule.audit
                          RichRule.accept
                      }
                      richRule {
                          family FirewalldFamily.IPv4
                          richIcmpBlock "echo-request"
                      }
                      richRule {
                          family FirewalldFamily.IPv4
                          forwardPort (tcpPort 8123) (Some "198.51.100.20") (Some (tcpPort 8124))
                      }
                      richRule {
                          family FirewalldFamily.IPv4
                          richSourcePort (udpPort 53000)
                          RichRule.accept
                      }
                      richRule {
                          family FirewalldFamily.IPv6
                          richPort (tcpPort 443)
                          RichRule.nflog (Some "100") (Some "catalogue") (Some 64)
                          RichRule.accept
                      }
                      richRule {
                          family FirewalldFamily.IPv4
                          richPriority -5
                          sourceAddress "192.0.2.0/24"
                          RichRule.mark "0x1/0xff"
                      }
                      richRule { family FirewalldFamily.IPv4; richMasquerade }
                      richRule { family FirewalldFamily.IPv4; RichRule.tcpMssClamp }
                      richRule { family FirewalldFamily.IPv4; RichRule.tcpMssClampValue 1200 } ]
            }
            zone "catalogue-accept" { target FirewalldTarget.Accept }
            zone "catalogue-reject" { target FirewalldTarget.Reject }
            policy "catalogue-policy" {
                ingressZones [ "catalogue-edge" ]
                egressZones [ "ANY" ]
                target FirewalldTarget.Continue
                priority -30
                services [ "catalogue-service" ]
                transportPorts [ tcpPort 8443 ]
                protocols [ "esp" ]
                masquerade true
                sourcePorts [ udpPort 5353 ]
                forwardPort (tcpPort 8444) (Some "198.51.100.30") (Some (tcpPort 8445))
                icmpBlocks [ "echo-request" ]
                short "Catalogue policy"
                Defined.description "Policy native catalogue coverage"
                version "2"
                richRules
                    [ richRule {
                          family FirewalldFamily.IPv4
                          richPriority -5
                          invertSource (sourceIPSet "catalogue-ip-set")
                          invertDestination (destinationAddress "203.0.113.20")
                          richService "catalogue-base"
                          RichRule.nflog (Some "101") (Some "policy") (Some 128)
                          RichRule.limitBurst 5 FirewalldLimitUnit.Second 2
                          RichRule.accept
                      }
                      richRule {
                          family FirewalldFamily.IPv4
                          sourceAddress "192.0.2.0/24"
                          destinationIPSet "catalogue-ip-set"
                          richProtocol "gre"
                          RichRule.mark "0x2"
                      }
                      richRule {
                          family FirewalldFamily.IPv4
                          richPort (tcpPort 8081)
                          RichRule.log (Some "info") (Some "policy: ")
                          RichRule.drop
                      }
                      richRule {
                          family FirewalldFamily.IPv4
                          sourceMac "02:00:00:00:00:03"
                          richSourcePort (tcpPort 40000)
                          RichRule.rejectWith "tcp-reset"
                      }
                      richRule { family FirewalldFamily.IPv6; richIcmpType "echo-request"; RichRule.audit; RichRule.accept }
                      richRule { family FirewalldFamily.IPv4; RichRule.tcpMssClampValue 1360 } ]
            }
            Defined.service "catalogue-base" {
                short "Base transport"
                Defined.description "Base service included by the catalogue service"
                version "1"
                servicePorts [ tcpPort 8080 ]
                protocols [ "esp" ]
                sourcePorts [ udpPort 5353 ]
            }
            Defined.service "catalogue-service" {
                short "Catalogue service"
                Defined.description "Service exercises module, helper, include and destination"
                version "2"
                servicePorts [ tcpPortRange 8440 8443; udpPort 53 ]
                protocols [ "gre" ]
                sourcePorts [ tcpPort 1024 ]
                includes [ "catalogue-base" ]
                helpers [ "ftp" ]
                modules [ "nf_conntrack_ftp" ]
                serviceDestination (Some "198.51.100.0/24") (Some "2001:db8::/64")
            }
            helper "ftp" {
                short "FTP helper"
                Defined.description "Catalogue helper"
                version "1"
                helperModule "nf_conntrack_ftp"
                helperFamily FirewalldFamily.IPv4
                helperPorts [ tcpPort 21 ]
            }
            icmpType "catalogue-echo" {
                short "Catalogue echo"
                Defined.description "IPv4 and IPv6 destinations"
                version "1"
                icmpDestinations [ FirewalldFamily.IPv4; FirewalldFamily.IPv6 ]
            }
            yield! ipsets
            yield! settings |> List.map (fun (key, value) -> setting key value)
            strictForwardPorts true
        }

    let export (render: string -> string) (outputDirectory: string) =
        System.IO.Directory.CreateDirectory outputDirectory |> ignore
        for item in specification.Objects do
            let directory =
                match item.Kind with
                | "zone" -> "zones"
                | "policy" -> "policies"
                | "service" -> "services"
                | "helper" -> "helpers"
                | "ipset" -> "ipsets"
                | "icmptype" -> "icmptypes"
                | "settings" -> ""
                | _ -> invalidOp ("Unexpected catalogue object kind: " + item.Kind)
            if directory <> "" then
                let path = System.IO.Path.Combine(outputDirectory, directory, item.Name + ".xml")
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName path) |> ignore
                let xml = render item.Configuration
                System.IO.File.WriteAllText(path, xml)
        let daemonSettings =
            specification.Objects
            |> List.choose (fun item ->
                if item.Kind = "settings" then
                    let config = FirewalldModel.parse item.Configuration
                    Some(FirewalldModel.settingKey config, config.SettingValue.Value)
                else None)
        let strictForwardPorts =
            specification.StrictForwardPorts
            |> Option.map (fun enabled -> "StrictForwardPorts", if enabled then "yes" else "no")
            |> Option.toList
        let settingsText =
            (daemonSettings @ strictForwardPorts)
            |> List.sortBy fst
            |> List.map (fun (key, value) -> key + "=" + value)
            |> String.concat "\n"
        System.IO.File.WriteAllText(System.IO.Path.Combine(outputDirectory, "firewalld.conf"), settingsText + "\n")
