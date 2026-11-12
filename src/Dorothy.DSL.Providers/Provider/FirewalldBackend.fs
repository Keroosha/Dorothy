namespace Dorothy.DSL.Provider

open System
open System.Text.Json
open System.Text.Json.Nodes
open System.Threading
open Dorothy.DSL

type FirewalldSnapshot =
    { Exists: bool
      Actual: string
      InSync: bool }

module FirewalldBackend =
    let private invoke operation connection ownerId configuration cancellationToken =
        let payload = JsonObject()
        payload["operation"] <- JsonValue.Create(operation: string)
        payload["ownerId"] <- JsonValue.Create(ownerId: string)
        payload["configuration"] <- JsonValue.Create(configuration: string)
        SshTransport.runHelper connection "firewalld" "firewalld" (payload.ToJsonString()) cancellationToken

    let parseSnapshot (output: string) =
        use document = JsonDocument.Parse output
        let root = document.RootElement
        let properties = root.EnumerateObject() |> Seq.map (fun p -> p.Name) |> Seq.toList
        if properties.Length <> 3 || Set.ofList properties <> set [ "exists"; "actual"; "inSync" ] then
            invalidOp "Invalid firewalld helper snapshot."
        let exists = root.GetProperty("exists").GetBoolean()
        let actual = root.GetProperty("actual").GetString()
        let inSync = root.GetProperty("inSync").GetBoolean()
        if isNull actual || (not exists && (actual <> "" || inSync)) then invalidOp "Inconsistent firewalld helper snapshot."
        { Exists = exists; Actual = actual; InSync = inSync }

    let read connection ownerId configuration (ct: CancellationToken) =
        task {
            let! output = invoke "read" connection ownerId configuration ct
            return parseSnapshot output
        }

    let apply connection ownerId configuration (ct: CancellationToken) =
        task {
            let! output = invoke "apply" connection ownerId configuration ct
            return parseSnapshot output
        }

    let delete connection ownerId configuration (ct: CancellationToken) =
        task {
            let! output = invoke "delete" connection ownerId configuration ct
            use document = JsonDocument.Parse output
            if document.RootElement.ValueKind <> JsonValueKind.Object || not (document.RootElement.EnumerateObject() |> Seq.isEmpty) then
                invalidOp "Invalid firewalld delete response."
        }
