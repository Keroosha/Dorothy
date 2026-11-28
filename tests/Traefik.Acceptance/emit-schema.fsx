// Inspect the exact provider response; pipe stdout to jq for the Traefik + shared types projection.
open System.Threading
open Pulumi.Experimental.Provider
open Dorothy.DSL.Provider
let schema = DorothyProvider().GetSchema(GetSchemaRequest(0, "", ""), CancellationToken.None).Result.Schema
printfn "%s" schema
