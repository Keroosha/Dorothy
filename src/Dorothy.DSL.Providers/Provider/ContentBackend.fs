namespace Dorothy.DSL.Provider

open System
open System.Text.Json.Nodes
open System.Threading
open System.Threading.Tasks

/// The request body is sent exclusively over the native helper's stdin transport.
module ContentBackend =
    type Snapshot =
        { Exists: bool
          InSync: bool
          Hashes: string }

    let payload (operation: string) (specification: string) (source: string) (hashes: string) =
        let request = JsonNode.Parse(specification).AsObject()
        request["operation"] <- JsonValue.Create operation
        request["hashes"] <- JsonNode.Parse hashes
        if operation = "apply" then
            for property in JsonNode.Parse(source).AsObject() do
                if property.Key <> "url" && property.Key <> "headers" && property.Key <> "data" then
                    invalidOp "Unsupported content payload property."
                request[property.Key] <- property.Value.DeepClone()
        request.ToJsonString()

    let invoke connection operation specification source hashes (ct: CancellationToken) : Task<Snapshot> =
        task {
            let body = payload operation specification source hashes
            let! output = SshTransport.runHelper connection "content" "host content" body ct
            try
                let result = JsonNode.Parse(output).AsObject()
                if result.Count <> 3 then invalidOp "Invalid content helper snapshot."
                return
                    { Exists = result["exists"].GetValue<bool>()
                      InSync = result["inSync"].GetValue<bool>()
                      Hashes = result["hashes"].AsObject().ToJsonString() }
            with _ -> return raise (InvalidOperationException("Invalid content helper snapshot."))
        }

module ServiceBackend =
    type Snapshot =
        { Exists: bool
          InSync: bool
          Active: bool
          Enabled: bool }

    let payload (operation: string) (specification: string) (restart: bool) =
        let request = JsonNode.Parse(specification).AsObject()
        request["operation"] <- JsonValue.Create operation
        request["restart"] <- JsonValue.Create restart
        request.ToJsonString()

    let invoke connection operation specification restart (ct: CancellationToken) : Task<Snapshot> =
        task {
            let! output = SshTransport.runHelper connection "service" "systemd service" (payload operation specification restart) ct
            try
                let result = JsonNode.Parse(output).AsObject()
                if result.Count <> 4 then invalidOp "Invalid service helper snapshot."
                return
                    { Exists = result["exists"].GetValue<bool>()
                      InSync = result["inSync"].GetValue<bool>()
                      Active = result["active"].GetValue<bool>()
                      Enabled = result["enabled"].GetValue<bool>() }
            with _ -> return raise (InvalidOperationException("Invalid service helper snapshot."))
        }
