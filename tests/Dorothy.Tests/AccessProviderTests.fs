namespace Dorothy.Tests

open System
open System.Collections.Immutable
open System.Threading
open Dorothy.DSL.Provider
open NUnit.Framework
open Pulumi.Experimental
open Pulumi.Experimental.Provider

[<RequireQualifiedAccess>]
module private AccessProviderValues =
    let map (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do
            builder.Add(key, value)
        PropertyValue(builder.ToImmutable())

    let inputMap (entries: seq<string * PropertyValue>) =
        let builder = ImmutableDictionary.CreateBuilder<string, PropertyValue>(StringComparer.Ordinal)
        for key, value in entries do
            builder.Add(key, value)
        builder.ToImmutable()

    let array (values: seq<PropertyValue>) = PropertyValue(ImmutableArray.CreateRange(values))
    let text (value: string) = PropertyValue(value)
    let number (value: int) = PropertyValue(float value)
    let boolean (value: bool) = PropertyValue(value)

    let mapContents (value: PropertyValue) =
        let mutable contents = ImmutableDictionary<string, PropertyValue>.Empty
        if value.TryGetMap(&contents) then contents else failwith "Expected a map property value."

    let requestUrn token = Pulumi.Urn(sprintf "urn:pulumi:unit::unit::%s::access" token)

    let check token inputs =
        let request =
            CheckRequest(
                requestUrn token,
                ImmutableDictionary<string, PropertyValue>.Empty,
                inputs,
                ImmutableArray<byte>.Empty
            )
        DorothyProvider().Check(request, CancellationToken.None).GetAwaiter().GetResult()

    let createPreview token inputs =
        let request = CreateRequest(requestUrn token, inputs, TimeSpan.FromSeconds(1.0), true)
        DorothyProvider().Create(request, CancellationToken.None).GetAwaiter().GetResult()

    let diff token oldInputs oldOutputs newInputs =
        let request =
            DiffRequest(
                requestUrn token,
                "owned-resource",
                oldOutputs,
                newInputs,
                ImmutableArray<string>.Empty,
                oldInputs
            )
        DorothyProvider().Diff(request, CancellationToken.None).GetAwaiter().GetResult()

    let connection address =
        map [
            "address", text address
            "user", text "operator"
        ]

    let usersInput address (userFields: PropertyValue) =
        inputMap [
            "connection", connection address
            "groups", map Seq.empty
            "users", map [ "operator", userFields ]
        ]

    let userFieldsWithShell (hash: PropertyValue) shell =
        map [
            "kind", text "human"
            "primaryGroup", map [ "kind", text "private" ]
            "supplementaryGroups", map [ "mode", text "managed"; "names", array Seq.empty ]
            "home", map [ "kind", text "create"; "path", text "/home/operator"; "mode", number 448 ]
            "shell", text shell
            "password", map [ "kind", text "hash"; "hash", hash; "update", text "onCreate" ]
            "authorizedKeys", map [ "mode", text "managed"; "keys", array Seq.empty ]
        ]

    let userFields hash = userFieldsWithShell hash "/bin/bash"

    let sudoGrantWithAuthentication authentication =
        map [
            "subjects", array [ map [ "kind", text "user"; "name", text "operator" ] ]
            "runAs", map [ "kind", text "all" ]
            "authentication", text authentication
            "allCommands", boolean true
            "commands", array Seq.empty
        ]

    let sudoGrant = sudoGrantWithAuthentication "passwordless"

    let sudoInput address grant =
        inputMap [
            "connection", connection address
            "grants", map [ "operator-admin", grant ]
        ]

    let usersActualWithShell shell =
        map [
            "groups", array Seq.empty
            "users", array [
                map [
                    "name", text "operator"
                    "exists", boolean true
                    "uid", number 1000
                    "gid", number 1000
                    "description", PropertyValue.Null
                    "home", text "/home/operator"
                    "shell", text shell
                    "locked", boolean false
                    "accountExpiry", PropertyValue.Null
                    "passwordPolicy", map [
                        "minDays", PropertyValue.Null
                        "maxDays", PropertyValue.Null
                        "warnDays", PropertyValue.Null
                        "inactiveDays", PropertyValue.Null
                    ]
                    "supplementaryGroups", array Seq.empty
                    "subordinateUids", array Seq.empty
                    "subordinateGids", array Seq.empty
                    "authorizedKeys", array Seq.empty
                ]
            ]
        ]

    let usersActual = usersActualWithShell "/bin/bash"
    let sudoActual =
        map [
            "filePath", text "/etc/sudoers.d/dorothy-test"
            "filePresent", boolean false
            "fileSha256", PropertyValue.Null
            "fileMode", PropertyValue.Null
            "fileOwnerUid", PropertyValue.Null
            "grants", array Seq.empty
        ]

    let sudoActualOwned =
        map [
            "filePath", text "/etc/sudoers.d/keroosha-operator-admin"
            "filePresent", boolean true
            "fileSha256", text (String('a', 64))
            "fileMode", number 288
            "fileOwnerUid", number 0
            "grants", array [ map [ "name", text "operator-admin"; "effectiveVerified", boolean true; "coverage", text "direct-user" ] ]
        ]

[<TestFixture>]
type AccessProviderTests() =
    [<Test>]
    member _.``Users Check marks nested password hashes secret and preview keeps outputs unknown``() =
        let token = "keroosha:debian:Users"
        let inputs = AccessProviderValues.usersInput "192.0.2.10" (AccessProviderValues.userFields (AccessProviderValues.text "$6$test-salt$UnrwlUJafStkUFYRI1nrV9EQCiKH.XdWBjnWnUDAN5Mbx/1Rhet84yuqCqN9bfvakkyX5P0qKTPUSK0BICn5M."))
        let checkResponse = AccessProviderValues.check token inputs
        let users = AccessProviderValues.mapContents checkResponse.Inputs["users"]
        let operatorFields = AccessProviderValues.mapContents users["operator"]
        let password = AccessProviderValues.mapContents operatorFields["password"]
        let preview = AccessProviderValues.createPreview token (ImmutableDictionary.CreateRange<string, PropertyValue>(checkResponse.Inputs))

        let hashIsProtected =
            checkResponse.Inputs["users"].IsSecret
            || users["operator"].IsSecret
            || operatorFields["password"].IsSecret
            || password["hash"].IsSecret

        Assert.That(checkResponse.Failures, Is.Empty)
        Assert.That(hashIsProtected, Is.True)
        Assert.That(preview.Id, Is.Empty)
        Assert.That(preview.Outputs["exists"].IsComputed, Is.True)
        Assert.That(preview.Outputs["inSync"].IsComputed, Is.True)
        Assert.That(preview.Outputs["actual"].IsComputed, Is.True)
        Assert.That(preview.Outputs["actual"].IsSecret, Is.False)

    [<Test>]
    member _.``Users Check preserves unknown nested password hashes``() =
        let token = "keroosha:debian:Users"
        let inputs = AccessProviderValues.usersInput "192.0.2.10" (AccessProviderValues.userFields PropertyValue.Computed)
        let response = AccessProviderValues.check token inputs
        let users = AccessProviderValues.mapContents response.Inputs["users"]
        let operatorFields = AccessProviderValues.mapContents users["operator"]
        let password = AccessProviderValues.mapContents operatorFields["password"]

        let hashIsProtected =
            response.Inputs["users"].IsSecret
            || users["operator"].IsSecret
            || operatorFields["password"].IsSecret
            || password["hash"].IsSecret

        Assert.That(response.Failures, Is.Empty)
        Assert.That(password["hash"].IsComputed, Is.True)
        Assert.That(hashIsProtected, Is.True)

    [<Test>]
    member _.``Users Check rejects malformed nested policy without disclosing hash``() =
        let token = "keroosha:debian:Users"
        let literalHash = "$6$test-salt$UnrwlUJafStkUFYRI1nrV9EQCiKH.XdWBjnWnUDAN5Mbx/1Rhet84yuqCqN9bfvakkyX5P0qKTPUSK0BICn5M."
        let malformedUser =
            AccessProviderValues.map [
                "kind", AccessProviderValues.text "human"
                "password", AccessProviderValues.map [
                    "kind", AccessProviderValues.text "hash"
                    "hash", AccessProviderValues.text literalHash
                ]
                "authorizedKeys", AccessProviderValues.map [ "mode", AccessProviderValues.text "invalid"; "keys", AccessProviderValues.array Seq.empty ]
            ]
        let response = AccessProviderValues.check token (AccessProviderValues.usersInput "192.0.2.10" malformedUser)
        let diagnostics =
            response.Failures
            |> Seq.map (fun failure -> failure.Property + ": " + failure.Reason)
            |> String.concat "\n"

        Assert.That(response.Failures, Is.Not.Empty)
        Assert.That(response.Failures |> Seq.exists (fun failure -> failure.Property.Contains("authorizedKeys", StringComparison.Ordinal)), Is.True)
        Assert.That(diagnostics, Does.Not.Contain(literalHash))

    [<Test>]
    member _.``Users Check rejects plaintext credentials and redacts diagnostics``() =
        let token = "keroosha:debian:Users"
        let plaintext = "literal-plaintext-password"
        let inputs = AccessProviderValues.usersInput "192.0.2.10" (AccessProviderValues.userFields (AccessProviderValues.text plaintext))
        let response = AccessProviderValues.check token inputs
        let diagnostics =
            response.Failures
            |> Seq.map (fun failure -> failure.Property + ": " + failure.Reason)
            |> String.concat "\n"

        Assert.That(response.Failures |> Seq.exists (fun failure -> failure.Property.Contains("password.hash", StringComparison.Ordinal)), Is.True)
        Assert.That(diagnostics, Does.Not.Contain(plaintext))

    [<Test>]
    member _.``Users Check rejects mutable fields on absent identities``() =
        let token = "keroosha:debian:Users"
        let inputs =
            AccessProviderValues.inputMap [
                "connection", AccessProviderValues.connection "192.0.2.10"
                "groups", AccessProviderValues.map [
                    "operators", AccessProviderValues.map [ "state", AccessProviderValues.text "absent"; "gid", AccessProviderValues.number 2200 ]
                ]
                "users", AccessProviderValues.map [
                    "operator", AccessProviderValues.map [
                        "state", AccessProviderValues.text "absent"
                        "existing", AccessProviderValues.text "reject"
                        "kind", AccessProviderValues.text "human"
                    ]
                ]
            ]
        let response = AccessProviderValues.check token inputs

        Assert.That(response.Failures |> Seq.exists (fun failure -> failure.Property = "groups.operators.gid"), Is.True)
        Assert.That(response.Failures |> Seq.exists (fun failure -> failure.Property = "users.operator.kind"), Is.True)

    [<Test>]
    member _.``Users Check rejects password update policy on a locked password``() =
        let token = "keroosha:debian:Users"
        let user =
            AccessProviderValues.map [
                "kind", AccessProviderValues.text "human"
                "password", AccessProviderValues.map [
                    "kind", AccessProviderValues.text "locked"
                    "update", AccessProviderValues.text "onCreate"
                ]
            ]
        let response = AccessProviderValues.check token (AccessProviderValues.usersInput "192.0.2.10" user)

        Assert.That(response.Failures |> Seq.exists (fun failure -> failure.Property = "users.operator.password.update"), Is.True)

    [<Test>]
    member _.``Users Check rejects inconsistent password lifetime policy``() =
        let token = "keroosha:debian:Users"
        let user =
            AccessProviderValues.map [
                "kind", AccessProviderValues.text "human"
                "passwordPolicy", AccessProviderValues.map [
                    "minDays", AccessProviderValues.number 30
                    "maxDays", AccessProviderValues.number 7
                ]
            ]
        let response = AccessProviderValues.check token (AccessProviderValues.usersInput "192.0.2.10" user)

        Assert.That(response.Failures |> Seq.exists (fun failure -> failure.Property = "users.operator.passwordPolicy.maxDays"), Is.True)

    [<Test>]
    member _.``Users Diff replaces changed connection address and repairs observed drift``() =
        let token = "keroosha:debian:Users"
        let secretHash = PropertyValue("$6$test-salt$UnrwlUJafStkUFYRI1nrV9EQCiKH.XdWBjnWnUDAN5Mbx/1Rhet84yuqCqN9bfvakkyX5P0qKTPUSK0BICn5M.", IsSecret = true)
        let desired = AccessProviderValues.usersInput "192.0.2.10" (AccessProviderValues.userFields secretHash)
        let moved = AccessProviderValues.usersInput "192.0.2.11" (AccessProviderValues.userFields secretHash)
        let outputs = AccessProviderValues.inputMap [ "exists", AccessProviderValues.boolean true; "inSync", AccessProviderValues.boolean false; "actual", AccessProviderValues.usersActual ]
        let response = AccessProviderValues.diff token desired outputs moved

        Assert.That(response.Changes.HasValue, Is.True)
        Assert.That(response.Changes.Value, Is.True)
        Assert.That(response.Replaces.Contains("connection.address"), Is.True)
        Assert.That(response.Diffs.Contains("inSync"), Is.True)

    [<Test>]
    member _.``Users Diff reports nested account configuration changes``() =
        let token = "keroosha:debian:Users"
        let hash = PropertyValue("$6$test-salt$UnrwlUJafStkUFYRI1nrV9EQCiKH.XdWBjnWnUDAN5Mbx/1Rhet84yuqCqN9bfvakkyX5P0qKTPUSK0BICn5M.", IsSecret = true)
        let oldInputs = AccessProviderValues.usersInput "192.0.2.10" (AccessProviderValues.userFieldsWithShell hash "/bin/bash")
        let newInputs = AccessProviderValues.usersInput "192.0.2.10" (AccessProviderValues.userFieldsWithShell hash "/usr/bin/zsh")
        let outputs = AccessProviderValues.inputMap [ "exists", AccessProviderValues.boolean true; "inSync", AccessProviderValues.boolean true; "actual", AccessProviderValues.usersActual ]
        let response = AccessProviderValues.diff token oldInputs outputs newInputs

        Assert.That(response.Changes.HasValue, Is.True)
        Assert.That(response.Changes.Value, Is.True)
        Assert.That(response.Diffs.Contains("users"), Is.True)

    [<Test>]
    member _.``Users Diff ignores unknown actual while deferring unknown drift flags``() =
        let token = "keroosha:debian:Users"
        let hash = PropertyValue("$6$test-salt$UnrwlUJafStkUFYRI1nrV9EQCiKH.XdWBjnWnUDAN5Mbx/1Rhet84yuqCqN9bfvakkyX5P0qKTPUSK0BICn5M.", IsSecret = true)
        let inputs = AccessProviderValues.usersInput "192.0.2.10" (AccessProviderValues.userFields hash)
        let actualUnknown = AccessProviderValues.inputMap [ "exists", AccessProviderValues.boolean true; "inSync", AccessProviderValues.boolean true; "actual", PropertyValue.Computed ]
        let flagsUnknown = AccessProviderValues.inputMap [ "exists", PropertyValue.Computed; "inSync", AccessProviderValues.boolean true; "actual", AccessProviderValues.usersActual ]
        let ignoredActual = AccessProviderValues.diff token inputs actualUnknown inputs
        let deferredFlags = AccessProviderValues.diff token inputs flagsUnknown inputs

        Assert.That(ignoredActual.Changes.HasValue, Is.True)
        Assert.That(ignoredActual.Changes.Value, Is.False)
        Assert.That(deferredFlags.Changes.HasValue, Is.False)



    [<Test>]
    member _.``Sudo Check accepts unrestricted run-as grant but rejects implicit command arguments``() =
        let token = "keroosha:debian:Sudo"
        let valid = AccessProviderValues.check token (AccessProviderValues.sudoInput "192.0.2.10" AccessProviderValues.sudoGrant)
        let invalidCommand =
            AccessProviderValues.map [
                "subjects", AccessProviderValues.array [ AccessProviderValues.map [ "kind", AccessProviderValues.text "group"; "name", AccessProviderValues.text "operators" ] ]
                "runAs", AccessProviderValues.map [ "kind", AccessProviderValues.text "specific"; "user", AccessProviderValues.text "root" ]
                "authentication", AccessProviderValues.text "required"
                "allCommands", AccessProviderValues.boolean false
                "commands", AccessProviderValues.array [
                    AccessProviderValues.map [
                        "path", AccessProviderValues.text "/usr/bin/apt"
                        "arguments", AccessProviderValues.map [ "kind", AccessProviderValues.text "exact" ]
                    ]
                ]
            ]
        let invalid = AccessProviderValues.check token (AccessProviderValues.sudoInput "192.0.2.10" invalidCommand)

        Assert.That(valid.Failures, Is.Empty)
        Assert.That(invalid.Failures, Is.Not.Empty)

    [<Test>]
    member _.``Sudo Check accepts literal regex anchors but rejects line injection``() =
        let checkArguments value =
            let grant =
                AccessProviderValues.map [
                    "subjects", AccessProviderValues.array [ AccessProviderValues.map [ "kind", AccessProviderValues.text "user"; "name", AccessProviderValues.text "operator" ] ]
                    "runAs", AccessProviderValues.map [ "kind", AccessProviderValues.text "specific"; "user", AccessProviderValues.text "root" ]
                    "authentication", AccessProviderValues.text "passwordless"
                    "allCommands", AccessProviderValues.boolean false
                    "commands", AccessProviderValues.array [
                        AccessProviderValues.map [
                            "path", AccessProviderValues.text "/usr/bin/printf"
                            "arguments", AccessProviderValues.map [ "kind", AccessProviderValues.text "exact"; "value", AccessProviderValues.text value ]
                        ]
                    ]
                ]
            AccessProviderValues.check "keroosha:debian:Sudo" (AccessProviderValues.sudoInput "192.0.2.10" grant)

        let literal = checkArguments "^literal$"
        let injected = checkArguments "^literal$\nALL=(ALL) NOPASSWD: ALL"
        Assert.That(literal.Failures, Is.Empty)
        Assert.That(
            injected.Failures |> Seq.exists (fun failure -> failure.Property = "grants.operator-admin.commands[0].arguments.value"),
            Is.True
        )

    [<Test>]
    member _.``Sudo Diff requests reconciliation when observed grants drift``() =
        let token = "keroosha:debian:Sudo"
        let inputs = AccessProviderValues.sudoInput "192.0.2.10" AccessProviderValues.sudoGrant
        let outputs = AccessProviderValues.inputMap [ "exists", AccessProviderValues.boolean true; "inSync", AccessProviderValues.boolean false; "actual", AccessProviderValues.sudoActual ]
        let response = AccessProviderValues.diff token inputs outputs inputs

        Assert.That(response.Changes.HasValue, Is.True)
        Assert.That(response.Changes.Value, Is.True)
        Assert.That(response.Diffs.Contains("inSync"), Is.True)

    [<Test>]
    member _.``Sudo Diff reports desired grant changes separately from drift``() =
        let token = "keroosha:debian:Sudo"
        let oldInputs = AccessProviderValues.sudoInput "192.0.2.10" (AccessProviderValues.sudoGrantWithAuthentication "required")
        let newInputs = AccessProviderValues.sudoInput "192.0.2.10" (AccessProviderValues.sudoGrantWithAuthentication "passwordless")
        let outputs = AccessProviderValues.inputMap [ "exists", AccessProviderValues.boolean true; "inSync", AccessProviderValues.boolean true; "actual", AccessProviderValues.sudoActualOwned ]
        let response = AccessProviderValues.diff token oldInputs outputs newInputs

        Assert.That(response.Changes.HasValue, Is.True)
        Assert.That(response.Changes.Value, Is.True)
        Assert.That(response.Diffs.Contains("grants"), Is.True)

    [<Test>]
    member _.``Sudo Diff ignores unknown actual while deferring unknown drift flags``() =
        let token = "keroosha:debian:Sudo"
        let inputs = AccessProviderValues.sudoInput "192.0.2.10" AccessProviderValues.sudoGrant
        let actualUnknown = AccessProviderValues.inputMap [ "exists", AccessProviderValues.boolean true; "inSync", AccessProviderValues.boolean true; "actual", PropertyValue.Computed ]
        let flagsUnknown = AccessProviderValues.inputMap [ "exists", PropertyValue.Computed; "inSync", AccessProviderValues.boolean true; "actual", AccessProviderValues.sudoActual ]
        let ignoredActual = AccessProviderValues.diff token inputs actualUnknown inputs
        let deferredFlags = AccessProviderValues.diff token inputs flagsUnknown inputs

        Assert.That(ignoredActual.Changes.HasValue, Is.True)
        Assert.That(ignoredActual.Changes.Value, Is.False)
        Assert.That(deferredFlags.Changes.HasValue, Is.False)

    [<Test>]
    member _.``Sudo Diff replaces a changed connection address``() =
        let token = "keroosha:debian:Sudo"
        let oldInputs = AccessProviderValues.sudoInput "192.0.2.10" AccessProviderValues.sudoGrant
        let newInputs = AccessProviderValues.sudoInput "192.0.2.11" AccessProviderValues.sudoGrant
        let outputs = AccessProviderValues.inputMap [ "exists", AccessProviderValues.boolean true; "inSync", AccessProviderValues.boolean true; "actual", AccessProviderValues.sudoActualOwned ]
        let response = AccessProviderValues.diff token oldInputs outputs newInputs

        Assert.That(response.Changes.HasValue, Is.True)
        Assert.That(response.Changes.Value, Is.True)
        Assert.That(response.Replaces.Contains("connection.address"), Is.True)
        Assert.That(response.DeleteBeforeReplace, Is.True)
