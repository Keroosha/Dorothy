namespace Dorothy.DSL.Provider

open System
open System.Text.Json
open System.Text.Json.Nodes
open System.Threading

type DockerJobSnapshot =
    { Exists: bool
      Completed: bool }

module DockerJobBackend =
    let serializeRequest (operation: string) (containerId: string) (timeoutSeconds: int) =
        let request = JsonObject()
        request["operation"] <- JsonValue.Create(operation)
        request["containerId"] <- JsonValue.Create(containerId)
        request["timeoutSeconds"] <- JsonValue.Create(timeoutSeconds)
        request.ToJsonString()

    let parseSnapshot (output: string) =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement
            let properties = root.EnumerateObject() |> Seq.toArray
            if properties.Length <> 2 || (properties |> Array.map (fun p -> p.Name) |> Set.ofArray) <> Set.ofList [ "exists"; "completed" ] then
                invalidOp "Unexpected Docker job snapshot properties."
            let exists = root.GetProperty("exists").GetBoolean()
            let completed = root.GetProperty("completed").GetBoolean()
            if completed && not exists then invalidOp "An absent Docker job cannot be completed."
            { Exists = exists; Completed = completed }
        with _ -> invalidOp "Remote Docker job helper returned an invalid snapshot."

    let invoke connection operation containerId timeoutSeconds (ct: CancellationToken) =
        task {
            let payload = serializeRequest operation containerId timeoutSeconds
            let! output = SshTransport.runHelper connection "docker-job" "Docker job" payload ct
            let snapshot = parseSnapshot output
            if operation = "apply" && not snapshot.Completed then
                invalidOp "Remote Docker job did not complete successfully."
            return snapshot
        }
