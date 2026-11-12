namespace Dorothy.DSL

open System
open System.IO
open System.Text
open System.Text.Json.Nodes
open System.Security.Cryptography
open System.Collections.Immutable
open Pulumi

module HostContentInputs =
    let private digest (bytes: byte array) = SHA256.HashData bytes |> Convert.ToHexStringLower
    let private map (mapping: 'T -> 'U) (value: Output<'T>) = value.Apply(Func<'T, 'U>(mapping))

    /// Identity excludes acquisition details. Header names are descriptive, never restart triggers.
    let identity (specification: string) =
        let node = JsonNode.Parse(specification).AsObject()
        node.Remove("headerNames") |> ignore
        node.ToJsonString()

    let fingerprint specification = identity specification |> Encoding.UTF8.GetBytes |> digest

    let resolve (item: HostContentItem) =
        let data =
            match item.Kind with
            | "text" -> item.Value.Value |> DockerStringInput.resolve |> map (Encoding.UTF8.GetBytes >> Convert.ToBase64String)
            | "file" ->
                let load = task {
                    try
                        let! bytes = File.ReadAllBytesAsync(item.Source.Value)
                        return Convert.ToBase64String bytes
                    with _ -> return raise (InvalidOperationException("Unable to read local content source."))
                }
                Output.Create<string> load
            | _ -> Output.Create ""
        let specification =
            data |> map (fun encoded ->
                let node = JsonObject()
                node["kind"] <- JsonValue.Create item.Kind
                node["ownership"] <- JsonValue.Create(if item.Ownership = ContentOwnership.Managed then "managed" else "createOnly")
                if item.Kind <> "directory" then
                    let hash = item.Sha256 |> Option.defaultWith (fun () -> encoded |> Convert.FromBase64String |> digest)
                    node["sha256"] <- JsonValue.Create hash
                item.Format |> Option.iter (fun format -> node["format"] <- JsonValue.Create(match format with Zip -> "zip" | TarGz -> "tarGz" | TarZst -> "tarZst"))
                let names = JsonArray()
                for name, _ in item.Headers |> List.sortBy fst do names.Add(JsonValue.Create name)
                node["headerNames"] <- names
                let targets = JsonArray()
                for target in item.Targets |> List.sortBy _.Path do
                    let entry = JsonObject()
                    entry["path"] <- JsonValue.Create target.Path
                    entry["source"] <- JsonValue.Create target.Source
                    entry["mode"] <- JsonValue.Create target.Mode
                    target.Owner |> Option.iter (fun value -> entry["owner"] <- JsonValue.Create value)
                    target.Group |> Option.iter (fun value -> entry["group"] <- JsonValue.Create value)
                    targets.Add entry
                node["targets"] <- targets
                node.ToJsonString())
        let headers = item.Headers |> List.map (snd >> DockerStringInput.resolveSecret) |> List.toArray |> Output.All<string>
        let payload =
            Output.Tuple(data, headers)
            |> map (fun struct (encoded, values: ImmutableArray<string>) ->
                let node = JsonObject()
                if encoded <> "" || item.Kind = "text" || item.Kind = "file" then node["data"] <- JsonValue.Create encoded
                item.Url |> Option.iter (fun value -> node["url"] <- JsonValue.Create value)
                let headers = JsonObject()
                for index, (name, _) in item.Headers |> List.indexed do
                    let value = values[index]
                    if value |> Seq.exists (fun c -> c = '\r' || c = '\n' || c = '\000') then invalidArg "headers" "HTTP headers cannot contain line breaks or NUL."
                    headers[name] <- JsonValue.Create value
                node["headers"] <- headers
                node.ToJsonString())
            |> Output.CreateSecret<string>
        specification, payload

    let service (specification: HostServiceSpec) =
        let node = JsonObject()
        node["name"] <- JsonValue.Create specification.Name
        node["managed"] <- JsonValue.Create specification.Managed
        node["configuration"] <- JsonValue.Create specification.Configuration
        node.ToJsonString()
