// Run with `dotnet fsi -I:<published-provider> -r:Pulumi.dll -r:pulumi-resource-keroosha.dll compare-admission.fsx`.
// No SSH. Emit only fixed case identifiers and observed decisions, never configuration or diagnostics.
open System.Collections.Immutable
open System.Text.Json.Nodes
open System.Threading
open Dorothy.DSL.Provider
open Pulumi.Experimental
open Pulumi.Experimental.Provider

let empty = ImmutableDictionary<string, PropertyValue>.Empty
let obj pairs =
    List.fold (fun (m: ImmutableDictionary<string, PropertyValue>) (k, v) -> m.Add(k, v)) empty pairs |> PropertyValue
let text (s: string) = PropertyValue(s)
let legacy =
    empty.Add("connection", obj ["address", text "offline.invalid"; "user", text "test"])
        .Add("entryPoints", obj [("web", PropertyValue(8088.))])
        .Add("routers", obj []).Add("resolvers", obj []).Add("certificates", obj [])
let otherHost =
    obj ["entryPoint", text "web"; "host", text "echo.test"; "backend", text "http://192.0.2.31:19080"
         "tls", obj ["kind", text "none"; "name", text ""]]
let root (s:string) =
    JsonNode.Parse(s).AsObject() |> ignore // A malformed fixture cannot count as a policy rejection.
    legacy.Add("configuration",PropertyValue(s))
let svc = """{"echo":{"loadBalancer":{"servers":[{"address":"127.0.0.1:39100"}]}}}"""
let tcp (tls:string) (rule:string) = root (sprintf """{"dynamic":{"tcp":{"routers":{"r":{"entryPoints":["web"],"service":"echo","rule":"%s"%s}},"services":%s},"tls":{"options":{"strict":{"minVersion":"VersionTLS12"}}}}}""" rule tls svc)
let staticFields fields = root (sprintf """{"static":{%s}}""" fields)
let ep attrs = staticFields (sprintf """"entryPoints":{"test":{"address":"127.0.0.1:38080",%s}}""" attrs)
let eab key = staticFields (sprintf """"certificatesResolvers":{"e":{"acme":{"httpChallenge":{"entryPoint":"web"},"eab":{"kid":"test","hmacEncoded":"%s"}}}}""" key)
let lb field = root (sprintf """{"dynamic":{"tcp":{"services":{"s":{"loadBalancer":{"servers":[{"address":"127.0.0.1:39100"}],"serversTransport":"transport"%s}}},"serversTransports":{"transport":{"dialTimeout":"1s"}}}}}""" field)
let testCases = [
    "unambiguous_named_transport", true, lb ""
    "ignored_loadbalancer_proxy", false, lb ",\"proxyProtocol\":{\"version\":2}"
    "ignored_loadbalancer_delay", false, lb ",\"terminationDelay\":\"10ms\""
    "passthrough_with_termination_policy", false, tcp ",\"tls\":{\"passthrough\":true,\"options\":\"strict\"}" "HostSNI(`echo.test`)"
    "sni_match_without_tls", false, tcp "" "HostSNI(`echo.test`)"
    "catchall_without_tls", true, tcp "" "HostSNI(`*`)"
    "overlapping_udp_routers", false, root (sprintf """{"static":{"entryPoints":{"datagram":{"address":"127.0.0.1:38123/udp"}}},"dynamic":{"udp":{"routers":{"a":{"entryPoints":["datagram"],"service":"echo"},"b":{"entryPoints":["datagram"],"service":"echo"}},"services":%s}}}""" svc)
    "mapped_listener_collision", false, staticFields """"entryPoints":{"alias":{"address":"[::ffff:127.0.0.1]:19080/tcp"}}"""
    "mapped_trust_all", false, ep """"proxyProtocol":{"trustedIPs":["::ffff:0.0.0.0/96"]}"""
    "empty_proxy_trust", false, ep """"proxyProtocol":{}"""
    "zero_telemetry_interval", false, staticFields """"metrics":{"statsD":{"address":"127.0.0.1:38125","pushInterval":"0s"}}"""
    "native_eab_base64url", true, eab "-_8"
    "standard_base64_not_base64url", false, eab "+/8="
    "nonlocal_numeric_same_port", true, legacy.SetItem("routers", obj [("r", otherHost)])
    "service_middleware", true, root """{"dynamic":{"http":{"middlewares":{"path":{"addPrefix":{"prefix":"/before"}}},"services":{"s":{"middlewares":["path"],"loadBalancer":{"servers":[{"url":"http://127.0.0.1:38127"}]}}}}}}"""
    "layered_router", true, root """{"dynamic":{"http":{"routers":{"p":{"entryPoints":["web"],"rule":"Host(`layer.test`)"},"c":{"parentRefs":["p"],"rule":"Method(`GET`)","service":"s"}},"services":{"s":{"loadBalancer":{"servers":[{"url":"http://127.0.0.1:38127"}]}}}}}}"""
]
let provider = TraefikProvider()
let urn = Pulumi.Urn("urn:pulumi:compare::fixture::keroosha:debian:Traefik::unit")
let output = JsonArray()
let mutable conforms = true
for name, expected, inputs in testCases do
    let accepted = provider.Check(CheckRequest(urn, empty, inputs, ImmutableArray<byte>.Empty), CancellationToken.None).Result.Failures.Count = 0
    conforms <- conforms && accepted = expected
    let result = JsonObject()
    result["case"] <- JsonValue.Create(name)
    result["expected"] <- JsonValue.Create(expected)
    result["observed"] <- JsonValue.Create(accepted)
    output.Add(result)
printfn "%s" (output.ToJsonString())
if fsi.CommandLineArgs |> Array.contains "--assert-current" then
    if not conforms then failwith "One or more admission outcomes differ from the declared contract."
