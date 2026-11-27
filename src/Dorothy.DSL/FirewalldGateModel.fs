#if HOST_HELPER
namespace Dorothy.HostHelper
#else
namespace Dorothy.DSL
#endif

open System
open System.Globalization
open System.Text.Json.Nodes

/// The boundary checked by the Docker start gate: a named, negative-priority DROP
/// for a specified set of transit ingress zones, with docker in its egress zones.
module FirewalldGateModel =
    type Fence =
        { Name: string
          Priority: int
          Ingress: Set<string>
          Egress: Set<string> }

    let private zones (values: string list) =
        if values.IsEmpty then invalidArg "zones" "A Docker fence cannot use an empty policy direction."
        let result = values |> List.map (FirewalldModel.nativeReference "zone" "zone") |> Set.ofList
        if result.Count <> values.Length || result.Contains "HOST" || (result.Contains "ANY" && result.Count <> 1) then
            invalidArg "zones" "Expected unique transit zones or ANY."
        result

    let private create name priority ingress egress =
        if priority < -32768 || priority >= 0 then invalidArg "priority" "Docker fence priority must be negative and within the native range."
        let fence = { Name = FirewalldModel.token "policy" 18 name; Priority = priority; Ingress = zones ingress; Egress = zones egress }
        if not (fence.Egress.Contains "docker") then invalidArg "egress" "The Docker fence must include the docker zone."
        fence

    let parseArguments name (priority: string) (ingress: string) (egress: string) =
        match Int32.TryParse(priority, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture) with
        | true, p -> create name p (ingress.Split(',') |> Array.toList) (egress.Split(',') |> Array.toList)
        | _ -> invalidArg "priority" "Invalid Docker fence priority."

    let ofPolicy (policy: FirewalldModel.Configuration) =
        create policy.Name policy.Priority policy.Ingress policy.Egress

    let arguments (fence: Fence) =
        [| fence.Name; fence.Priority.ToString(CultureInfo.InvariantCulture); String.concat "," fence.Ingress; String.concat "," fence.Egress |]

    let encode fences =
        let zoneArray (items: Set<string>) =
            let result = JsonArray()
            for name in items do result.Add(JsonValue.Create name)
            result
        let result = JsonArray()
        for fence in fences do
            let row = JsonObject()
            row["name"] <- JsonValue.Create fence.Name
            row["priority"] <- JsonValue.Create fence.Priority
            row["ingress"] <- zoneArray fence.Ingress
            row["egress"] <- zoneArray fence.Egress
            result.Add row
        result

    let decode (node: JsonNode) =
        if isNull node then invalidArg "dockerFence" "A policy list is required."
        let rows = node.AsArray()
        if rows.Count = 0 then invalidArg "dockerFence" "At least one policy is required."
        rows |> Seq.map (fun item ->
            let row = item.AsObject()
            if row.Count <> 4 then invalidArg "dockerFence" "Invalid Docker fence."
            let names (key: string) = row[key].AsArray() |> Seq.map (fun x -> x.GetValue<string>()) |> Seq.toList
            create (row["name"].GetValue<string>()) (row["priority"].GetValue<int>()) (names "ingress") (names "egress"))
        |> Seq.toList

    // The early prerequisite owns no fence or Docker zone. An empty list is
    // never a valid final guard, including when upgrading an existing stack.
    let decodeService (name: string) (node: JsonNode) =
        if name.EndsWith("-docker-firewall-bootstrap.service", StringComparison.Ordinal) then
            if isNull node || node.AsArray().Count <> 0 then invalidArg "dockerFence" "Bootstrap takes no policies."
            []
        elif name.EndsWith("-docker-firewall-guard.service", StringComparison.Ordinal) then decode node
        else invalidArg "dockerFence" "Unexpected Docker admission service name."
