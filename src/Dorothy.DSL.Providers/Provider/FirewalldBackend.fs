namespace Dorothy.DSL.Provider

open System
open System.Text.Json
open System.Text.Json.Nodes
open System.Net
open System.Collections.Concurrent
open System.Threading.Tasks
open System.Threading
open Dorothy.DSL

type FirewalldSnapshot =
    { Exists: bool
      Actual: string
      InSync: bool
      PermanentInSync: bool
      RuntimeObserved: bool
      RuntimeInSync: bool }

module FirewalldBackend =
    let private hostGates = ConcurrentDictionary<string, SemaphoreSlim>(StringComparer.OrdinalIgnoreCase)
    let private hostKey (address: string) =
        match IPAddress.TryParse address with
        | true, value -> value.ToString()
        | _ -> address.TrimEnd('.')

    let private withHostGate (connection: SshConnection) (ct: CancellationToken) (action: unit -> Task<'T>) =
        task {
            let gate = hostGates.GetOrAdd(hostKey connection.Address, fun _ -> new SemaphoreSlim(1, 1))
            do! gate.WaitAsync ct
            try return! action()
            finally gate.Release() |> ignore
        }
    let private invoke (fresh: bool) (operation: string) (connection: SshConnection) (ownerId: string) (configuration: string) (transactionNonce: string option) (cancellationToken: CancellationToken) =
        let payload = JsonObject()
        payload["operation"] <- JsonValue.Create(operation: string)
        payload["ownerId"] <- JsonValue.Create(ownerId: string)
        payload["configuration"] <- JsonValue.Create(configuration: string)
        transactionNonce |> Option.iter (fun nonce -> payload["transactionNonce"] <- JsonValue.Create nonce)
        let request = payload.ToJsonString()
        if fresh then
            SshTransport.runHelperFreshConnection connection "firewalld" "firewalld transaction confirmation" request cancellationToken
        else
            SshTransport.runHelper connection "firewalld" "firewalld" request cancellationToken

    let private propertyNames (root: JsonElement) =
        root.EnumerateObject() |> Seq.map (fun property -> property.Name) |> Set.ofSeq

    let private readBool (root: JsonElement) (name: string) = root.GetProperty(name).GetBoolean()

    let private optionalBool (root: JsonElement) (name: string) =
        let mutable value = Unchecked.defaultof<JsonElement>
        if root.TryGetProperty(name, &value) then Some(value.GetBoolean()) else None

    let private readNonce (root: JsonElement) =
        let nonce =
            match root.TryGetProperty "transactionNonce" with
            | true, value when value.ValueKind = JsonValueKind.String -> value.GetString()
            | _ -> invalidOp "Firewalld mutation response has no transaction nonce."
        if isNull nonce || nonce.Length <> 32
           || nonce |> Seq.exists (fun c -> not ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) then
            invalidOp "Invalid firewalld transaction nonce."
        nonce

    let private confirm connection ownerId configuration nonce cancellationToken =
        task {
            let! output = invoke true "confirm" connection ownerId configuration (Some nonce) cancellationToken
            use document = JsonDocument.Parse output
            if document.RootElement.ValueKind <> JsonValueKind.Object || not (Seq.isEmpty (document.RootElement.EnumerateObject())) then
                invalidOp "Invalid firewalld confirmation response."
        }

    let parseSnapshot (output: string) =
        use document = JsonDocument.Parse output
        let root = document.RootElement
        if root.ValueKind <> JsonValueKind.Object then invalidOp "Invalid firewalld helper snapshot."
        let properties = propertyNames root
        let legacy = set [ "exists"; "actual"; "inSync" ]
        let current = set [ "exists"; "actual"; "inSync"; "permanentInSync"; "runtimeObserved"; "runtimeInSync" ]
        let optional = set [ "permanentActual"; "runtimeActual"; "activationReceipt"; "runtimeLimit"; "transactionNonce" ]
        if properties = legacy then
            let exists = readBool root "exists"
            let actual = root.GetProperty("actual").GetString()
            if isNull actual || (not exists && actual <> "") then invalidOp "Inconsistent legacy firewalld helper snapshot."
            { Exists = exists
              Actual = actual
              InSync = false
              PermanentInSync = readBool root "inSync"
              RuntimeObserved = false
              RuntimeInSync = false }
        else
            if not (Set.isSubset current properties) || not (Set.isSubset properties (Set.union current optional)) then
                invalidOp "Invalid firewalld helper snapshot."
            let exists = readBool root "exists"
            let actual = root.GetProperty("actual").GetString()
            let inSync = readBool root "inSync"
            let permanentInSync = readBool root "permanentInSync"
            let runtimeObserved = readBool root "runtimeObserved"
            let runtimeInSync = readBool root "runtimeInSync"
            let activationReceipt = optionalBool root "activationReceipt" = Some true
            if isNull actual || (not runtimeObserved && runtimeInSync)
               || (inSync && (not permanentInSync || not (if runtimeObserved then runtimeInSync else activationReceipt))) then
                invalidOp "Inconsistent firewalld helper snapshot."
            { Exists = exists
              Actual = actual
              InSync = inSync
              PermanentInSync = permanentInSync
              RuntimeObserved = runtimeObserved
              RuntimeInSync = runtimeInSync }

    let read connection ownerId configuration (ct: CancellationToken) =
        withHostGate connection ct (fun () -> task {
            let! output = invoke false "read" connection ownerId configuration None ct
            return parseSnapshot output
        })
    let apply connection ownerId configuration (ct: CancellationToken) =
        withHostGate connection ct (fun () -> task {
            let! output = invoke false "apply" connection ownerId configuration None ct
            use document = JsonDocument.Parse output
            let root = document.RootElement
            if propertyNames root <> set [ "unchanged" ] || not (readBool root "unchanged") then
                let nonce = readNonce root
                let staged = parseSnapshot output
                let activationReceipt = optionalBool root "activationReceipt" = Some true
                if not staged.PermanentInSync
                   || (staged.RuntimeObserved && not staged.RuntimeInSync)
                   || (not staged.RuntimeObserved && not activationReceipt) then
                    invalidOp "Firewalld mutation did not converge before fresh-connection confirmation."
                do! confirm connection ownerId configuration nonce ct
            let! confirmed = invoke false "read" connection ownerId configuration None ct
            let snapshot = parseSnapshot confirmed
            if not snapshot.InSync then invalidOp "Firewalld apply did not leave the owned resource in sync."
            return snapshot
        })

    let delete connection ownerId configuration (ct: CancellationToken) =
        withHostGate connection ct (fun () -> task {
            let! output = invoke false "delete" connection ownerId configuration None ct
            use document = JsonDocument.Parse output
            let root = document.RootElement
            if root.ValueKind <> JsonValueKind.Object then invalidOp "Invalid firewalld delete response."
            let fields = propertyNames root
            if fields = set [ "unchanged" ] && readBool root "unchanged" then ()
            elif fields = set [ "transactionNonce" ] then
                let nonce = readNonce root
                do! confirm connection ownerId configuration nonce ct
            else invalidOp "Invalid firewalld delete response."
        })
