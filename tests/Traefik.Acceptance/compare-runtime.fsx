// Run using `dotnet fsi --reference:<managed-host-helper.dll> compare-runtime.fsx <capture-root>`.
// <capture-root> holds the pinned guest outputs from capture-effective-graph.sh.
open System.IO
open System.Text.Json
open System.Text.Json.Nodes
open Dorothy.HostHelper

let root = fsi.CommandLineArgs[1]
let file mode name = Path.Combine(root, mode, name)
let element path =
    use stream = File.OpenRead(path)
    use doc = JsonDocument.Parse(stream)
    doc.RootElement.Clone()
let readApi mode : Traefik.ApiConfiguration =
    { EntryPoints = element (file mode "entrypoints.json"); Version = element (file mode "version.json")
      RawData = element (file mode "rawdata.json"); AdminPort = 38307 }
let cases = [
    "effective_literal_map", "base", "base", true
    "inherited_and_layered_routes", "model", "model", true
    "automatic_priority", "rank", "rank", true
    "explicit_zero_priority", "rank-zero", "rank-zero", true
    "stale_priority_changed_backend", "rank", "rank-stale", false
    "chain_without_fabricated_child_usage", "chain", "chain", true
    "reverse_chain", "chain-reverse", "chain-reverse", true
    "tcp_middleware_without_fabricated_usage", "tcp-middleware", "tcp-middleware", true
    "wrong_chain_order", "chain", "chain-reverse", false
]
let results = JsonArray()
let mutable correct = true
let record name (expected:bool) (observed:bool) =
    let item=JsonObject()
    item["case"] <- JsonValue.Create<string>(name)
    item["expected"] <- JsonValue.Create(expected)
    item["observed"] <- JsonValue.Create(observed)
    results.Add(item)
    correct <- correct && expected = observed
for name, desired, actual, expected in cases do
    let staticData = Some(File.ReadAllBytes(file desired "static.json"))
    let dynamicData = Some(File.ReadAllBytes(file desired "dynamic.yml"))
    record name expected (Traefik.apiMatchesRuntime (Some(readApi actual)) staticData dynamicData)
record "trusted_peers_match" true (Traefik.apiMatchesStatic (Some(readApi "base")) (Some(File.ReadAllBytes(file "base" "static.json"))))
record "trusted_peers_stale_with_same_bind" false (Traefik.apiMatchesStatic (Some(readApi "drift")) (Some(File.ReadAllBytes(file "base" "static.json"))))
printfn "%s" (results.ToJsonString())
if Array.contains "--assert-current" fsi.CommandLineArgs && not correct then failwith "Unexpected effective graph observations."
