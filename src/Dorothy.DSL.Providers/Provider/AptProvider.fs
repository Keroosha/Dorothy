namespace Dorothy.DSL.Provider

open System
open System.Text.Json
open System.Collections.Generic
open System.Collections.Immutable
open System.Text.RegularExpressions
open System.Threading
open System.Threading.Tasks
open Pulumi.Experimental
open Pulumi.Experimental.Provider

module private AptProviderLogic =
    [<Literal>]
    let ResourceToken = "keroosha:debian:AptPackageSet"


    type NormalizedInputs =
        { Values: Dictionary<string, PropertyValue>
          HasUnknowns: bool
          Failures: ResizeArray<CheckFailure> }

    type ParsedInputs =
        { Values: Dictionary<string, PropertyValue>
          Connection: SshConnection
          DesiredVersions: Map<string, string option>
          PackageNames: string list }

    let private packageNamePattern = Regex("^[a-z0-9][a-z0-9+.-]+$", RegexOptions.CultureInvariant)

    let private validPackageVersion (version: string) =
        if String.IsNullOrEmpty(version) || version.Length > 255 then
            false
        else
            let separator = version.IndexOf(':')
            let epochValid, upstream =
                if separator < 0 then
                    true, version
                else
                    let epoch = version.Substring(0, separator)
                    let validEpoch = epoch.Length > 0 && (epoch |> Seq.forall (fun value -> value >= '0' && value <= '9'))
                    validEpoch, version.Substring(separator + 1)
            let allowed value =
                (value >= 'a' && value <= 'z')
                || (value >= 'A' && value <= 'Z')
                || (value >= '0' && value <= '9')
                || value = '.'
                || value = '+'
                || value = '~'
                || value = '-'
            epochValid
            && upstream.Length > 0
            && upstream[0] >= '0'
            && upstream[0] <= '9'
            && (separator < 0 || not (upstream.Contains(':')))
            && (upstream |> Seq.forall allowed)
    let private schema =
        """{
  "name": "keroosha",
  "version": "0.1.0",
  "displayName": "Dorothy",
  "description": "Dorothy Debian host infrastructure provider.",
  "types": {
    "keroosha:debian:SshConnection": {
      "type": "object",
      "description": "SSH connection details for an existing Debian host.",
      "properties": {
        "address": { "type": "string" },
        "user": { "type": "string" },
        "port": { "type": "integer", "default": 22 },
        "identityFile": { "type": "string" }
      },
      "required": ["address", "user"]
    },
    "keroosha:debian:AptPackage": {
      "type": "object",
      "description": "An optional exact Debian package version constraint.",
      "properties": {
        "version": { "type": "string" }
      }
    }
  },
  "resources": {
    "keroosha:debian:AptPackageSet": {
      "description": "Manages the declared Debian APT package set on an existing SSH host.",
      "inputProperties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "packages": {
          "type": "object",
          "additionalProperties": { "$ref": "#/types/keroosha:debian:AptPackage" }
        }
      },
      "requiredInputs": ["connection", "packages"],
      "properties": {
        "connection": { "$ref": "#/types/keroosha:debian:SshConnection" },
        "packages": {
          "type": "object",
          "additionalProperties": { "$ref": "#/types/keroosha:debian:AptPackage" }
        },
        "installedVersions": {
          "type": "object",
          "additionalProperties": { "type": "string" }
        },
        "managedPackages": {
          "type": "array",
          "items": { "type": "string" }
        }
      },
      "required": ["connection", "packages", "installedVersions", "managedPackages"]
    }
  }
}"""

    let private hasControlCharacters (value: string) =
        value |> Seq.exists (fun character -> Char.IsControl(character))

    let private validPackageName (name: string) =
        name.Length <= 255 && packageNamePattern.IsMatch(name)

    let private tryGetMap (value: PropertyValue) =
        let mutable result = ImmutableDictionary<string, PropertyValue>.Empty
        if value.TryGetMap(&result) then Some result else None

    let private tryGetArray (value: PropertyValue) =
        let mutable result = ImmutableArray<PropertyValue>.Empty
        if value.TryGetArray(&result) then Some result else None

    let private tryGetString (value: PropertyValue) =
        let mutable result = Unchecked.defaultof<string>
        if value.TryGetString(&result) then Some result else None

    let rec private containsSecret (value: PropertyValue) =
        if value.IsSecret then
            true
        else
            match tryGetMap value with
            | Some values -> values.Values |> Seq.exists containsSecret
            | None ->
                match tryGetArray value with
                | Some values -> values |> Seq.exists containsSecret
                | None -> false

    let rec private containsUnknown (value: PropertyValue) =
        if value.IsComputed then
            true
        else
            match tryGetMap value with
            | Some values -> values.Values |> Seq.exists containsUnknown
            | None ->
                match tryGetArray value with
                | Some values -> values |> Seq.exists containsUnknown
                | None -> false

    let private hasUnknownInputs (values: ImmutableDictionary<string, PropertyValue>) =
        values.Values |> Seq.exists containsUnknown

    let private addFailure (failures: ResizeArray<CheckFailure>) property reason =
        failures.Add(CheckFailure(property, reason))

    let private withDependencies (source: PropertyValue) (replacement: PropertyValue) =
        replacement.WithDependencies(source.Dependencies)

    let private makeMapValue (source: PropertyValue) (values: ImmutableDictionary<string, PropertyValue>) =
        withDependencies source (PropertyValue(values))

    let private buildMap (values: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for (key, value) in values do
            builder[key] <- value
        builder.ToImmutable()

    let private inputDictionary (values: ImmutableDictionary<string, PropertyValue>) =
        let result = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        for entry in values do
            result.Add(entry.Key, entry.Value)
        result

    let private normalizeConnection (source: PropertyValue) (values: ImmutableDictionary<string, PropertyValue>) (failures: ResizeArray<CheckFailure>) =
        let normalized = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        for entry in values do
            normalized.Add(entry.Key, entry.Value)

        for entry in values do
            if entry.Key <> "address" && entry.Key <> "user" && entry.Key <> "port" && entry.Key <> "identityFile" then
                addFailure failures ("connection." + entry.Key) "This connection property is not supported."

        let mutable hasUnknown = false

        let normalizeRequiredString name validate reason =
            match values.TryGetValue(name) with
            | false, _ -> addFailure failures ("connection." + name) "This property is required."
            | true, value when value.IsComputed -> hasUnknown <- true
            | true, value ->
                match tryGetString value with
                | None -> addFailure failures ("connection." + name) "Expected a string."
                | Some text ->
                    let canonical = text.Trim()
                    if String.IsNullOrWhiteSpace(canonical) || not (validate canonical) then
                        addFailure failures ("connection." + name) reason
                    else
                        normalized[name] <- withDependencies value (PropertyValue(canonical))

        normalizeRequiredString "address" (fun text -> not (text.StartsWith("-", StringComparison.Ordinal)) && not (text.Contains('@')) && not (text |> Seq.exists (fun character -> Char.IsWhiteSpace(character))) && not (hasControlCharacters text)) "Expected a non-empty SSH host address without whitespace or '@'."
        normalizeRequiredString "user" (fun text -> not (text.StartsWith("-", StringComparison.Ordinal)) && not (text.Contains('/')) && not (text.Contains('@')) && not (text |> Seq.exists (fun character -> Char.IsWhiteSpace(character))) && not (hasControlCharacters text)) "Expected a non-empty SSH user without whitespace, '/', or '@'."

        match values.TryGetValue("port") with
        | false, _ -> normalized["port"] <- PropertyValue(22.0)
        | true, value when value.IsComputed -> hasUnknown <- true
        | true, value when value.IsNull -> normalized["port"] <- PropertyValue(22.0)
        | true, value ->
            let mutable number = 0.0
            if not (value.TryGetNumber(&number)) || Double.IsNaN(number) || Double.IsInfinity(number) || number <> Math.Truncate(number) || number < 1.0 || number > 65535.0 then
                addFailure failures "connection.port" "Expected an integer SSH port from 1 through 65535."
            else
                normalized["port"] <- withDependencies value (PropertyValue(number))

        match values.TryGetValue("identityFile") with
        | false, _ -> ()
        | true, value when value.IsComputed -> hasUnknown <- true
        | true, value when value.IsNull -> normalized.Remove("identityFile") |> ignore
        | true, value ->
            match tryGetString value with
            | None -> addFailure failures "connection.identityFile" "Expected a string when identityFile is provided."
            | Some path when String.IsNullOrWhiteSpace(path) -> normalized.Remove("identityFile") |> ignore
            | Some path when hasControlCharacters path -> addFailure failures "connection.identityFile" "identityFile must not contain control characters."
            | Some path -> normalized["identityFile"] <- withDependencies value (PropertyValue(path))

        hasUnknown, makeMapValue source (buildMap (normalized |> Seq.map (fun entry -> entry.Key, entry.Value)))

    let private normalizePackageValue packageName (source: PropertyValue) (values: ImmutableDictionary<string, PropertyValue>) (failures: ResizeArray<CheckFailure>) =
        let packagePath = "packages." + packageName
        let normalized = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        let mutable hasUnknown = false

        for entry in values do
            if entry.Key <> "version" then
                addFailure failures (packagePath + "." + entry.Key) "This package property is not supported."

        match values.TryGetValue("version") with
        | false, _ -> ()
        | true, version when version.IsComputed ->
            hasUnknown <- true
            normalized["version"] <- version
        | true, version when version.IsNull -> ()
        | true, version ->
            match tryGetString version with
            | None -> addFailure failures (packagePath + ".version") "Expected a string when version is provided."
            | Some text when not (validPackageVersion text) ->
                addFailure failures (packagePath + ".version") "Expected a valid exact Debian package version."
            | Some text -> normalized["version"] <- version

        hasUnknown, makeMapValue source (buildMap (normalized |> Seq.map (fun entry -> entry.Key, entry.Value)))

    let private normalizePackages (source: PropertyValue) (values: ImmutableDictionary<string, PropertyValue>) (failures: ResizeArray<CheckFailure>) =
        let normalized = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        let mutable hasUnknown = false

        for entry in values do
            if not (validPackageName entry.Key) then
                addFailure failures ("packages." + entry.Key) "Expected a valid Debian package name."
            elif entry.Value.IsComputed then
                hasUnknown <- true
                normalized[entry.Key] <- entry.Value
            else
                match tryGetMap entry.Value with
                | None -> addFailure failures ("packages." + entry.Key) "Expected a package object."
                | Some packageValues ->
                    let packageHasUnknown, packageValue = normalizePackageValue entry.Key entry.Value packageValues failures
                    hasUnknown <- hasUnknown || packageHasUnknown
                    normalized[entry.Key] <- packageValue

        hasUnknown, makeMapValue source (buildMap (normalized |> Seq.map (fun entry -> entry.Key, entry.Value)))

    let normalizeInputs (values: ImmutableDictionary<string, PropertyValue>) =
        let normalized = inputDictionary values
        let failures = ResizeArray<CheckFailure>()

        let unknownProperties = values.Keys |> Seq.filter (fun key -> key <> "connection" && key <> "packages") |> Seq.toArray
        for key in unknownProperties do
            addFailure failures key "This resource property is not supported."

        if values.Values |> Seq.exists containsSecret then
            for key in [ "connection"; "packages" ] do
                match values.TryGetValue(key) with
                | true, value when containsSecret value -> addFailure failures key "Secret values are not supported by this resource."
                | _ -> ()
            { Values = normalized; HasUnknowns = hasUnknownInputs values; Failures = failures }
        else
            let mutable hasUnknown = hasUnknownInputs values

            match values.TryGetValue("connection") with
            | false, _ -> addFailure failures "connection" "This property is required."
            | true, value when value.IsComputed -> hasUnknown <- true
            | true, value ->
                match tryGetMap value with
                | None -> addFailure failures "connection" "Expected a connection object."
                | Some connectionValues ->
                    let connectionUnknown, connectionValue = normalizeConnection value connectionValues failures
                    hasUnknown <- hasUnknown || connectionUnknown
                    normalized["connection"] <- connectionValue

            match values.TryGetValue("packages") with
            | false, _ -> addFailure failures "packages" "This property is required."
            | true, value when value.IsComputed -> hasUnknown <- true
            | true, value ->
                match tryGetMap value with
                | None -> addFailure failures "packages" "Expected an object keyed by Debian package name."
                | Some packageValues ->
                    let packagesUnknown, packagesValue = normalizePackages value packageValues failures
                    hasUnknown <- hasUnknown || packagesUnknown
                    normalized["packages"] <- packagesValue

            { Values = normalized; HasUnknowns = hasUnknown; Failures = failures }

    let private failIfFailures (failures: ResizeArray<CheckFailure>) =
        if failures.Count > 0 then
            let reasons = failures |> Seq.map (fun failure -> failure.Property + ": " + failure.Reason) |> String.concat " "
            invalidOp reasons

    let private failIfUnknown hasUnknown =
        if hasUnknown then invalidOp "AptPackageSet cannot be applied while one or more input values are unknown."

    let private getMap path (values: Dictionary<string, PropertyValue>) =
        match values.TryGetValue(path) with
        | true, value ->
            match tryGetMap value with
            | Some result -> result
            | None -> invalidOp (path + " must be an object.")
        | false, _ -> invalidOp (path + " is required.")

    let private getKnownString path (values: ImmutableDictionary<string, PropertyValue>) =
        match values.TryGetValue(path) with
        | true, value ->
            match tryGetString value with
            | Some result -> result
            | None -> invalidOp (path + " must be a known string.")
        | false, _ -> invalidOp (path + " is required.")

    let private parseInputs (values: Dictionary<string, PropertyValue>) =
        let connectionValues = getMap "connection" values
        let address = getKnownString "address" connectionValues
        let user = getKnownString "user" connectionValues
        let port =
            match connectionValues.TryGetValue("port") with
            | true, value ->
                let mutable number = 0.0
                if value.TryGetNumber(&number) && number >= 1.0 && number <= 65535.0 then int number
                else invalidOp "connection.port must be a known integer SSH port."
            | false, _ -> 22
        let identityFile =
            match connectionValues.TryGetValue("identityFile") with
            | true, value when value.IsNull -> None
            | true, value -> tryGetString value
            | false, _ -> None

        let packageValues = getMap "packages" values
        let desiredVersions =
            packageValues
            |> Seq.map (fun entry ->
                let package =
                    match tryGetMap entry.Value with
                    | Some package -> package
                    | None -> invalidOp ("packages." + entry.Key + " must be an object.")
                let version =
                    match package.TryGetValue("version") with
                    | true, value when value.IsNull -> None
                    | true, value ->
                        match tryGetString value with
                        | Some version -> Some version
                        | None -> invalidOp ("packages." + entry.Key + ".version must be a known string.")
                    | false, _ -> None
                entry.Key, version)
            |> Map.ofSeq

        { Values = values
          Connection =
            { Address = address
              User = user
              Port = port
              IdentityFile = identityFile }
          DesiredVersions = desiredVersions
          PackageNames = desiredVersions |> Map.toList |> List.map fst }

    let private normalizedKnownInputs (source: ImmutableDictionary<string, PropertyValue>) =
        let normalized = normalizeInputs source
        failIfFailures normalized.Failures
        failIfUnknown normalized.HasUnknowns
        parseInputs normalized.Values

    let private knownInputsFromOutputs (preferred: ImmutableDictionary<string, PropertyValue>) (fallback: ImmutableDictionary<string, PropertyValue>) =
        let result = Dictionary<string, PropertyValue>(StringComparer.Ordinal)
        for key in [ "connection"; "packages" ] do
            match preferred.TryGetValue(key) with
            | true, value -> result[key] <- value
            | false, _ ->
                match fallback.TryGetValue(key) with
                | true, value -> result[key] <- value
                | false, _ -> ()
        result

    let private stableId (urn: Pulumi.Urn) (connection: SshConnection) =
        urn.ToString() + "::" + connection.Address
    let resourceId (urn: Pulumi.Urn) (connection: SshConnection) = stableId urn connection
    let private mapKeyPath (property: string) (key: string) = property + "[" + JsonSerializer.Serialize<string>(key) + "]"

    let private stringPropertyMap (values: seq<string * PropertyValue>) =
        PropertyValue(buildMap values)

    let private stringMapValue (values: Map<string, string>) =
        values
        |> Map.toSeq
        |> Seq.map (fun (key, value) -> key, PropertyValue(value))
        |> stringPropertyMap

    let private namesArrayValue (names: string list) =
        names
        |> Seq.map (fun name -> PropertyValue(name))
        |> fun values -> ImmutableArray.CreateRange<PropertyValue>(values)
        |> fun values -> PropertyValue(values)

    let private sortedNames names = names |> Seq.distinct |> Seq.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right)) |> Seq.toList

    let private managedNamesFromOutputs (outputs: ImmutableDictionary<string, PropertyValue>) fallbackNames =
        match outputs.TryGetValue("managedPackages") with
        | false, _ -> fallbackNames
        | true, value ->
            match tryGetArray value with
            | None -> invalidOp "Stored managedPackages state must be an array."
            | Some entries ->
                let storedNames =
                    entries
                    |> Seq.map (fun entry ->
                        match tryGetString entry with
                        | Some name when validPackageName name -> name
                        | _ -> invalidOp "Stored managedPackages state contains an invalid package name.")
                Seq.append storedNames fallbackNames |> sortedNames

    let private installedVersionsFromOutputs (outputs: ImmutableDictionary<string, PropertyValue>) =
        match outputs.TryGetValue("installedVersions") with
        | false, _ -> Map.empty
        | true, value ->
            match tryGetMap value with
            | None -> invalidOp "Stored installedVersions state must be an object."
            | Some entries ->
                entries
                |> Seq.map (fun entry ->
                    if not (validPackageName entry.Key) then invalidOp "Stored installedVersions state contains an invalid package name."
                    match tryGetString entry.Value with
                    | Some version -> entry.Key, version
                    | None -> invalidOp "Stored installedVersions state contains an invalid version.")
                |> Map.ofSeq

    let private observedForManaged managed observed =
        let owned = Set.ofList managed
        observed |> Map.filter (fun name _ -> owned.Contains(name))

    let private outputProperties (inputs: ParsedInputs) (installed: Map<string, string>) (managed: string list) =
        let outputs = Dictionary<string, PropertyValue>(inputs.Values, StringComparer.Ordinal)
        outputs["installedVersions"] <- stringMapValue (observedForManaged managed installed)
        outputs["managedPackages"] <- namesArrayValue (sortedNames managed)
        outputs

    let private previewProperties (inputs: NormalizedInputs) =
        let outputs = Dictionary<string, PropertyValue>(inputs.Values, StringComparer.Ordinal)
        outputs["installedVersions"] <- PropertyValue.Computed
        let managedPackages =
            match inputs.Values.TryGetValue("packages") with
            | true, value ->
                match tryGetMap value with
                | Some packages -> namesArrayValue (packages.Keys |> sortedNames)
                | None -> PropertyValue.Computed
            | false, _ -> PropertyValue.Computed
        outputs["managedPackages"] <- managedPackages
        outputs

    let private requestTimeout (timeout: TimeSpan) =
        if timeout > TimeSpan.Zero then Some timeout else None

    let runWithTimeout (timeout: TimeSpan option) (outerToken: CancellationToken) (operation: CancellationToken -> Task<'T>) =
        task {
            use linked = CancellationTokenSource.CreateLinkedTokenSource(outerToken)
            match timeout with
            | Some value when value > TimeSpan.Zero -> linked.CancelAfter(value)
            | _ -> ()
            return! operation linked.Token
        }

    let private ensureToken (actual: string) =
        if actual <> ResourceToken then invalidOp "Unexpected resource token for the Dorothy provider."


    let private checkResponse (inputs: Dictionary<string, PropertyValue>) (failures: ResizeArray<CheckFailure>) =
        let response = CheckResponse()
        response.Inputs <- inputs
        response.Failures <- List<CheckFailure>(failures)
        response

    let private diffResponse changes diffs replaces detailed =
        let response = DiffResponse()
        response.Changes <- Nullable<bool>(changes)
        response.Diffs <- diffs
        response.Replaces <- replaces
        response.DetailedDiff <- detailed
        response

    let private addDiff (diffs: ResizeArray<string>) (details: Dictionary<string, PropertyDiff>) root path kind inputDiff =
        if not (details.ContainsKey(path)) then
            let propertyDiff = PropertyDiff()
            propertyDiff.Kind <- kind
            propertyDiff.InputDiff <- inputDiff
            details.Add(path, propertyDiff)
            // Diffs is a set of top-level keys; only DetailedDiff accepts paths.
            // SDK 3.116.2 does not set the wire HasDetailedDiff flag, so the
            // legacy keys must also support the engine's structural diff.
            if not (diffs.Contains(root)) then diffs.Add(root)

    let private newDiffResult changes (diffs: ResizeArray<string>) (replaces: ResizeArray<string>) (details: Dictionary<string, PropertyDiff>) =
        let response = diffResponse changes (List<string>(diffs)) (List<string>(replaces)) details
        response.DeleteBeforeReplace <- replaces.Count > 0
        response

    let private makeDetailedDiff (request: DiffRequest) =
        let previousInputs = knownInputsFromOutputs request.OldInputs request.OldOutputs
        let outputHasUnknown key =
            match request.OldOutputs.TryGetValue(key) with
            | true, value -> containsUnknown value
            | false, _ -> false
        if outputHasUnknown "installedVersions" || outputHasUnknown "managedPackages" then
            let response = DiffResponse()
            response.Changes <- Nullable<bool>()
            response
        elif not (previousInputs.ContainsKey("connection")) || not (previousInputs.ContainsKey("packages")) then
            if String.IsNullOrEmpty(request.Id) then
                let response = DiffResponse()
                response.Changes <- Nullable<bool>(true)
                response.Diffs <- List<string>()
                response.Replaces <- List<string>()
                response.DetailedDiff <- Dictionary<string, PropertyDiff>()
                response
            else
                invalidOp "Stored AptPackageSet state is missing its connection or package declaration."
        else
            let oldImmutable =
                previousInputs
                |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))
                |> fun values -> ImmutableDictionary.CreateRange<string, PropertyValue>(values)
            let oldNormalized = normalizeInputs oldImmutable
            let newNormalized = normalizeInputs request.NewInputs

            if oldNormalized.Failures.Count > 0 || newNormalized.Failures.Count > 0 then
                failIfFailures oldNormalized.Failures
                failIfFailures newNormalized.Failures

            if oldNormalized.HasUnknowns || newNormalized.HasUnknowns then
                let response = DiffResponse()
                response.Changes <- Nullable<bool>()
                response
            else
                let oldInputs = parseInputs oldNormalized.Values
                let newInputs = parseInputs newNormalized.Values
                let previousManaged = managedNamesFromOutputs request.OldOutputs oldInputs.PackageNames
                let previousOwned = Set.ofList previousManaged
                let desiredOwned = Set.ofList newInputs.PackageNames
                let oldObserved = installedVersionsFromOutputs request.OldOutputs
                let diffs = ResizeArray<string>()
                let replaces = ResizeArray<string>()
                let details = Dictionary<string, PropertyDiff>(StringComparer.Ordinal)

                let add root path kind inputDiff = addDiff diffs details root path kind inputDiff
                let addReplace path =
                    add "connection" path PropertyDiffKind.UpdateReplace true
                    if not (replaces.Contains(path)) then replaces.Add(path)

                if oldInputs.Connection.Address <> newInputs.Connection.Address then addReplace "connection.address"
                if oldInputs.Connection.Port <> newInputs.Connection.Port then add "connection" "connection.port" PropertyDiffKind.Update true
                if oldInputs.Connection.User <> newInputs.Connection.User then add "connection" "connection.user" PropertyDiffKind.Update true
                if oldInputs.Connection.IdentityFile <> newInputs.Connection.IdentityFile then add "connection" "connection.identityFile" PropertyDiffKind.Update true

                let packageNames = Set.union previousOwned desiredOwned |> Set.toList |> List.sortWith (fun left right -> StringComparer.Ordinal.Compare(left, right))
                for name in packageNames do
                    let wasOwned = previousOwned.Contains(name)
                    let isDesired = desiredOwned.Contains(name)
                    if wasOwned && not isDesired then
                        add "packages" (mapKeyPath "packages" name) PropertyDiffKind.Delete true
                    elif not wasOwned && isDesired then
                        add "packages" (mapKeyPath "packages" name) PropertyDiffKind.Add true
                    else
                        let oldVersion = oldInputs.DesiredVersions |> Map.tryFind name |> Option.flatten
                        let newVersion = newInputs.DesiredVersions |> Map.tryFind name |> Option.flatten
                        if oldVersion <> newVersion then
                            add "packages" (mapKeyPath "packages" name + ".version") PropertyDiffKind.Update true

                    if isDesired then
                        let desiredVersion = newInputs.DesiredVersions |> Map.tryFind name |> Option.flatten
                        let actualVersion = oldObserved |> Map.tryFind name
                        let drifted =
                            match desiredVersion, actualVersion with
                            | Some required, Some installed -> required <> installed
                            | Some _, None -> true
                            | None, None -> true
                            | None, Some _ -> false
                        if drifted then
                            add "installedVersions" (mapKeyPath "installedVersions" name) PropertyDiffKind.Update false

                let hasChanges = diffs.Count > 0
                newDiffResult hasChanges diffs replaces details


    let createPreviewResponse (inputs: NormalizedInputs) =
        let response = CreateResponse()
        response.Id <- String.Empty
        response.Outputs <- previewProperties inputs
        response

    let createResponse (ownerId: string) (inputs: ParsedInputs) (snapshot: AptSnapshot) =
        let response = CreateResponse()
        response.Id <- ownerId
        response.Outputs <- outputProperties inputs snapshot.InstalledVersions snapshot.ManagedPackages
        response

    let updatePreviewResponse (inputs: NormalizedInputs) =
        let response = UpdateResponse()
        response.Outputs <- previewProperties inputs
        response

    let updateResponse (inputs: ParsedInputs) (snapshot: AptSnapshot) =
        let response = UpdateResponse()
        response.Outputs <- outputProperties inputs snapshot.InstalledVersions snapshot.ManagedPackages
        response

    let readResponse (id: string) (urn: Pulumi.Urn) (inputs: ParsedInputs) (installed: Map<string, string>) (managed: string list) =
        let response = ReadResponse()
        response.Id <- if String.IsNullOrEmpty(id) then stableId urn inputs.Connection else id
        response.Inputs <- inputs.Values
        response.Outputs <- outputProperties inputs installed managed
        response

    let mergedStateInputs (preferred: ImmutableDictionary<string, PropertyValue>) (fallback: ImmutableDictionary<string, PropertyValue>) =
        knownInputsFromOutputs preferred fallback
        |> Seq.map (fun entry -> KeyValuePair(entry.Key, entry.Value))
        |> fun values -> ImmutableDictionary.CreateRange<string, PropertyValue>(values)

    let parseStoredInputs values = normalizedKnownInputs values

    let managedNames outputs fallback = managedNamesFromOutputs outputs fallback
    let snapshotManagedNames (snapshot: AptSnapshot) fallback =
        Seq.append snapshot.ManagedPackages fallback |> sortedNames


    let ensureResourceToken requestType = ensureToken requestType

    let packageNames parsed = parsed.PackageNames

    let desiredVersions parsed = parsed.DesiredVersions

    let connection parsed = parsed.Connection


    let isProviderMetadata key =
        key = "version" || key = "pluginDownloadURL"

    let checkConfiguration (request: CheckRequest) =
        let failures = ResizeArray<CheckFailure>()
        for entry in request.NewInputs do
            if not (isProviderMetadata entry.Key) then
                addFailure failures entry.Key "Dorothy does not accept custom provider configuration properties."
        checkResponse (inputDictionary request.NewInputs) failures

    let configureResponse () =
        let response = ConfigureResponse()
        response.AcceptSecrets <- true
        response.AcceptResources <- false
        response.AcceptOutputs <- true
        response.SupportsPreview <- true
        response

    let diffConfiguration (request: DiffRequest) =
        let changed =
            request.OldInputs.Count <> request.NewInputs.Count
            || (request.NewInputs
                |> Seq.exists (fun entry ->
                    match request.OldInputs.TryGetValue(entry.Key) with
                    | true, oldValue -> not (oldValue.Equals(entry.Value))
                    | false, _ -> true))
        diffResponse changed (List<string>()) (List<string>()) (Dictionary<string, PropertyDiff>())

    let makeCheckResponse (request: CheckRequest) =
        if request.Type <> ResourceToken then
            let failures = ResizeArray<CheckFailure>()
            addFailure failures "" "Unexpected resource token for the Dorothy provider."
            checkResponse (inputDictionary request.NewInputs) failures
        else
            let normalized = normalizeInputs request.NewInputs
            checkResponse normalized.Values normalized.Failures

    let normalizeForOperation inputs = normalizedKnownInputs inputs
    let normalizeForPreview (inputs: ImmutableDictionary<string, PropertyValue>) =
        let normalized = normalizeInputs inputs
        failIfFailures normalized.Failures
        normalized

    let private oldStateManaged (oldOutputs: ImmutableDictionary<string, PropertyValue>) (oldInputs: ImmutableDictionary<string, PropertyValue>) =
        let source = mergedStateInputs oldInputs oldOutputs
        let parsed = normalizedKnownInputs source
        managedNamesFromOutputs oldOutputs parsed.PackageNames

    let oldManagedNames (oldOutputs: ImmutableDictionary<string, PropertyValue>) (oldInputs: ImmutableDictionary<string, PropertyValue>) =
        oldStateManaged oldOutputs oldInputs


    let makeDiff (request: DiffRequest) = makeDetailedDiff request


    let resourceOutputsForCheck (request: CheckRequest) = makeCheckResponse request

    let configurationCheck (request: CheckRequest) = checkConfiguration request

    let providerConfigurationDiff (request: DiffRequest) = diffConfiguration request

    let providerConfigurationResponse () = configureResponse ()

    let providerSchema = schema


    let timeoutForRequest timeout = requestTimeout timeout

[<Sealed>]
type AptProvider() =
    inherit Pulumi.Experimental.Provider.Provider()
    static member Version = "0.1.0"
    static member Schema = AptProviderLogic.providerSchema

    override _.GetSchema(_request: GetSchemaRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        let response = GetSchemaResponse()
        response.Schema <- AptProviderLogic.providerSchema
        Task.FromResult(response)

    override _.CheckConfig(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(AptProviderLogic.configurationCheck request)

    override _.DiffConfig(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(AptProviderLogic.providerConfigurationDiff request)

    override _.Configure(request: ConfigureRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        if request.Args.Keys |> Seq.exists (AptProviderLogic.isProviderMetadata >> not) then
            invalidOp "Dorothy does not accept custom provider configuration properties."
        Task.FromResult(AptProviderLogic.providerConfigurationResponse())

    override _.Check(request: CheckRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        Task.FromResult(AptProviderLogic.resourceOutputsForCheck request)

    override _.Diff(request: DiffRequest, ct: CancellationToken) =
        ct.ThrowIfCancellationRequested()
        AptProviderLogic.ensureResourceToken request.Type
        Task.FromResult(AptProviderLogic.makeDiff request)

    override _.Create(request: CreateRequest, ct: CancellationToken) =
        AptProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let normalized = AptProviderLogic.normalizeForPreview request.Inputs
            Task.FromResult(AptProviderLogic.createPreviewResponse normalized)
        else
            AptProviderLogic.runWithTimeout (AptProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = AptProviderLogic.normalizeForOperation request.Inputs
                    let connection = AptProviderLogic.connection inputs
                    let ownerId = AptProviderLogic.resourceId request.Urn connection
                    let! snapshot = AptBackend.apply connection ownerId [] (AptProviderLogic.desiredVersions inputs) operationToken
                    return AptProviderLogic.createResponse ownerId inputs snapshot
                })

    override _.Read(request: ReadRequest, ct: CancellationToken) =
        AptProviderLogic.ensureResourceToken request.Type
        AptProviderLogic.runWithTimeout None ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let source = AptProviderLogic.mergedStateInputs request.Inputs request.Outputs
                let inputs = AptProviderLogic.parseStoredInputs source
                let requestedNames = AptProviderLogic.packageNames inputs
                let ownerId =
                    if String.IsNullOrEmpty(request.Id) then AptProviderLogic.resourceId request.Urn (AptProviderLogic.connection inputs)
                    else request.Id
                let connection = AptProviderLogic.connection inputs
                let! snapshot = AptBackend.read connection ownerId requestedNames operationToken
                let managed = AptProviderLogic.snapshotManagedNames snapshot requestedNames
                return AptProviderLogic.readResponse ownerId request.Urn inputs snapshot.InstalledVersions managed
            })

    override _.Update(request: UpdateRequest, ct: CancellationToken) =
        AptProviderLogic.ensureResourceToken request.Type
        if request.Preview then
            let inputs = AptProviderLogic.normalizeForPreview request.NewInputs
            Task.FromResult(AptProviderLogic.updatePreviewResponse inputs)
        else
            AptProviderLogic.runWithTimeout (AptProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
                task {
                    operationToken.ThrowIfCancellationRequested()
                    let inputs = AptProviderLogic.normalizeForOperation request.NewInputs
                    let connection = AptProviderLogic.connection inputs
                    let ownerId = if String.IsNullOrEmpty(request.Id) then AptProviderLogic.resourceId request.Urn connection else request.Id
                    let oldManaged = AptProviderLogic.oldManagedNames request.OldOutputs request.OldInputs
                    let! snapshot = AptBackend.apply connection ownerId oldManaged (AptProviderLogic.desiredVersions inputs) operationToken
                    return AptProviderLogic.updateResponse inputs snapshot
                })

    override _.Delete(request: DeleteRequest, ct: CancellationToken) =
        AptProviderLogic.ensureResourceToken request.Type
        AptProviderLogic.runWithTimeout (AptProviderLogic.timeoutForRequest request.Timeout) ct (fun operationToken ->
            task {
                operationToken.ThrowIfCancellationRequested()
                let source = AptProviderLogic.mergedStateInputs request.OldInputs request.OldOutputs
                let inputs = AptProviderLogic.parseStoredInputs source
                let connection = AptProviderLogic.connection inputs
                let ownerId = if String.IsNullOrEmpty(request.Id) then AptProviderLogic.resourceId request.Urn connection else request.Id
                let managed = AptProviderLogic.managedNames request.OldOutputs (AptProviderLogic.packageNames inputs)
                let! _ = AptBackend.apply connection ownerId managed Map.empty operationToken
                return ()
            }) :> Task
