namespace Dorothy.Tests

open System
open System.IO
open System.Runtime.InteropServices
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open Dorothy.HostHelper
open NUnit.Framework

[<RequireQualifiedAccess>]
module private UsersTestNative =
    [<DllImport("libc", EntryPoint = "geteuid")>]
    extern uint32 private nativeGetEffectiveUserId ()


    [<DllImport("libc", EntryPoint = "chown", SetLastError = true)>]
    extern int private nativeChown (string path, uint32 owner, uint32 group)

    let effectiveUserId () = nativeGetEffectiveUserId ()

    let setOwner path uid gid =
        if nativeGetEffectiveUserId () = 0u then
            if nativeChown(path, uid, gid) <> 0 then
                invalidOp ("Could not set test fixture ownership (errno " + Marshal.GetLastPInvokeError().ToString() + ").")
        elif uid <> nativeGetEffectiveUserId () then
            invalidOp "A non-root behavior-test fixture can only use its own UID for account-owned paths."

[<Sealed>]
type private UsersFakeHost(root: string) =
    let calls = ResizeArray<string * string list * string option>()
    let mutable failNextChpasswd: string option = None
    let mutable failNextUseradd = false
    let mutable makeNextSshDirectoryUnsafe = false
    let connectionUid = if UsersTestNative.effectiveUserId () = 1000u then 1001 else 1000
    let connectionGid = connectionUid

    let mappedPath (logicalPath: string) =
        Path.Combine(root, logicalPath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar))

    let readRows logicalPath =
        let path = mappedPath logicalPath
        if File.Exists path then File.ReadAllLines(path) |> Array.filter (String.IsNullOrEmpty >> not) |> Array.toList else []

    let writeRows logicalPath rows =
        File.WriteAllLines(mappedPath logicalPath, List.toArray rows)

    let accountRows () = readRows "/etc/passwd"
    let groupRows () = readRows "/etc/group"
    let shadowRows () = readRows "/etc/shadow"

    let setPathOwner path uid gid = UsersTestNative.setOwner path uid gid

    let findUser name =
        accountRows ()
        |> List.tryFind (fun row -> row.Split(':')[0] = name)

    let changeUser name update =
        accountRows ()
        |> List.map (fun row ->
            let fields = row.Split(':')
            if fields[0] = name then
                update fields
                String.Join(":", fields)
            else row)
        |> writeRows "/etc/passwd"

    let changeShadow name password =
        shadowRows ()
        |> List.map (fun row ->
            let fields = row.Split(':')
            if fields[0] = name then fields[1] <- password
            String.Join(":", fields))
        |> writeRows "/etc/shadow"

    let changeGroup name update =
        groupRows ()
        |> List.map (fun row ->
            let fields = row.Split(':')
            if fields[0] = name then update fields
            String.Join(":", fields))
        |> writeRows "/etc/group"

    let setSupplementaryMembership userName memberships append =
        for row in groupRows () do
            let fields = row.Split(':')
            let current =
                if String.IsNullOrEmpty fields[3] then Set.empty
                else fields[3].Split(',', StringSplitOptions.RemoveEmptyEntries) |> Set.ofArray
            let next =
                if append then
                    if Set.contains fields[0] memberships then Set.add userName current else current
                else
                    let withoutUser = Set.remove userName current
                    if Set.contains fields[0] memberships then Set.add userName withoutUser else withoutUser
            if current <> next then
                changeGroup fields[0] (fun updated -> updated[3] <- String.Join(",", next))

    let lookup database selector =
        let rows = if database = "passwd" then accountRows () elif database = "group" then groupRows () else []
        let matching =
            rows
            |> List.filter (fun row ->
                let fields = row.Split(':')
                fields[0] = selector || (fields.Length > 2 && fields[2] = selector))
        match matching with
        | [] -> { ExitCode = 2; Stdout = ""; Stderr = "" }
        | values -> { ExitCode = 0; Stdout = String.Join("\n", values) + "\n"; Stderr = "" }

    let run executable arguments standardInput =
        calls.Add((executable, arguments, standardInput))
        match executable, arguments with
        | "getent", [ database; selector ] -> lookup database selector
        | "id", [ "-G"; userName ] ->
            match findUser userName with
            | None -> { ExitCode = 1; Stdout = ""; Stderr = "unknown user" }
            | Some row ->
                let fields = row.Split(':')
                let primary = fields[3]
                let supplementary =
                    groupRows ()
                    |> List.choose (fun group ->
                        let values = group.Split(':')
                        if values[3].Split(',', StringSplitOptions.RemoveEmptyEntries) |> Array.contains userName then Some values[2] else None)
                let ids = Set.ofList (primary :: supplementary) |> Set.toList |> List.sort
                { ExitCode = 0; Stdout = String.Join(" ", ids) + "\n"; Stderr = "" }
        | "groupadd", args ->
            let gid = args |> List.tryFindIndex ((=) "--gid") |> Option.bind (fun index -> List.tryItem (index + 1) args) |> Option.defaultWith (fun () -> invalidOp "groupadd fixture lacked --gid")
            let delimiter = args |> List.findIndex ((=) "--")
            let name = args[delimiter + 1]
            writeRows "/etc/group" (groupRows () @ [ name + ":x:" + gid + ":" ])
            { ExitCode = 0; Stdout = ""; Stderr = "" }
        | "groupdel", [ "--"; groupName ] ->
            match groupRows () |> List.tryFind (fun row -> row.Split(':')[0] = groupName) with
            | None -> { ExitCode = 6; Stdout = ""; Stderr = "unknown group" }
            | Some row ->
                let gid = row.Split(':')[2]
                if accountRows () |> List.exists (fun account -> account.Split(':')[3] = gid) then
                    { ExitCode = 8; Stdout = ""; Stderr = "group is still primary" }
                else
                    groupRows ()
                    |> List.filter (fun group -> group.Split(':')[0] <> groupName)
                    |> writeRows "/etc/group"
                    { ExitCode = 0; Stdout = ""; Stderr = "" }
        | "useradd", _ when failNextUseradd ->
            failNextUseradd <- false
            { ExitCode = 1; Stdout = ""; Stderr = "simulated interruption" }
        | "useradd", args ->
            let optionValue option = args |> List.tryFindIndex ((=) option) |> Option.bind (fun index -> List.tryItem (index + 1) args)
            let delimiter = args |> List.findIndex ((=) "--")
            let name = args[delimiter + 1]
            let uid = optionValue "--uid" |> Option.defaultWith (fun () -> invalidOp "useradd fixture lacked --uid")
            let gid = optionValue "--gid" |> Option.defaultWith (fun () -> invalidOp "useradd fixture lacked --gid")
            let description = optionValue "--comment" |> Option.defaultValue ""
            let home = optionValue "--home-dir" |> Option.defaultWith (fun () -> invalidOp "useradd fixture lacked --home-dir")
            let shell = optionValue "--shell" |> Option.defaultWith (fun () -> invalidOp "useradd fixture lacked --shell")
            writeRows "/etc/passwd" (accountRows () @ [ String.Join(":", [| name; "x"; uid; gid; description; home; shell |]) ])
            writeRows "/etc/shadow" (shadowRows () @ [ name + ":!:19000:0:99999:7:::" ])
            if List.contains "--create-home" args then
                let physicalHome = mappedPath home
                Directory.CreateDirectory(physicalHome) |> ignore
                File.SetUnixFileMode(physicalHome, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute ||| UnixFileMode.GroupRead ||| UnixFileMode.GroupExecute ||| UnixFileMode.OtherRead ||| UnixFileMode.OtherExecute)
                setPathOwner physicalHome (UInt32.Parse(uid)) (UInt32.Parse(gid))
            { ExitCode = 0; Stdout = ""; Stderr = "" }
        | "usermod", args ->
            let delimiter = args |> List.findIndex ((=) "--")
            let name = args[delimiter + 1]
            let options = args |> List.take delimiter
            let optionValue option = options |> List.tryFindIndex ((=) option) |> Option.bind (fun index -> List.tryItem (index + 1) options)
            optionValue "--comment" |> Option.iter (fun value -> changeUser name (fun fields -> fields[4] <- value))
            optionValue "--shell" |> Option.iter (fun value -> changeUser name (fun fields -> fields[6] <- value))
            match optionValue "--groups" with
            | Some value ->
                let members = if String.IsNullOrEmpty value then Set.empty else value.Split(',', StringSplitOptions.RemoveEmptyEntries) |> Set.ofArray
                setSupplementaryMembership name members (List.contains "--append" options)
            | None -> ()
            { ExitCode = 0; Stdout = ""; Stderr = "" }
        | "gpasswd", [ "--delete"; userName; groupName ] ->
            changeGroup groupName (fun fields ->
                let members = fields[3].Split(',', StringSplitOptions.RemoveEmptyEntries) |> Array.filter ((<>) userName)
                fields[3] <- String.Join(",", members))
            { ExitCode = 0; Stdout = ""; Stderr = "" }
        | "pgrep", [ "-u"; _ ] -> { ExitCode = 1; Stdout = ""; Stderr = "" }
        | "chpasswd", [ "--encrypted" ] ->
            match failNextChpasswd with
            | Some stderr ->
                failNextChpasswd <- None
                { ExitCode = 1; Stdout = ""; Stderr = stderr }
            | None ->
                let input = standardInput |> Option.defaultValue ""
                let delimiter = input.IndexOf(':')
                if delimiter <= 0 then { ExitCode = 1; Stdout = ""; Stderr = "malformed fixture stdin" }
                else
                    let userName = input.Substring(0, delimiter)
                    let passwordHash = input.Substring(delimiter + 1).TrimEnd('\n')
                    changeShadow userName passwordHash
                    { ExitCode = 0; Stdout = ""; Stderr = "" }
        | "userdel", [ "--"; userName ] ->
            accountRows ()
            |> List.filter (fun row -> row.Split(':')[0] <> userName)
            |> writeRows "/etc/passwd"
            shadowRows ()
            |> List.filter (fun row -> row.Split(':')[0] <> userName)
            |> writeRows "/etc/shadow"
            for group in groupRows () do
                let fields = group.Split(':')
                changeGroup fields[0] (fun updated ->
                    let members = fields[3].Split(',', StringSplitOptions.RemoveEmptyEntries) |> Array.filter ((<>) userName)
                    updated[3] <- String.Join(",", members))
            let userGroupsEnabled =
                File.ReadAllLines(mappedPath "/etc/login.defs")
                |> Array.exists (fun line -> line.Trim() = "USERGROUPS_ENAB yes")
            if userGroupsEnabled then
                match groupRows () |> List.tryFind (fun row -> row.Split(':')[0] = userName) with
                | Some group ->
                    let fields = group.Split(':')
                    let stillUsed = accountRows () |> List.exists (fun row -> row.Split(':')[3] = fields[2])
                    let members = fields[3].Split(',', StringSplitOptions.RemoveEmptyEntries)
                    if not stillUsed && members.Length = 0 then
                        groupRows () |> List.filter (fun row -> row.Split(':')[0] <> userName) |> writeRows "/etc/group"
                | None -> ()
            { ExitCode = 0; Stdout = ""; Stderr = "" }
        | "runuser", [ "--user"; userName; "--"; "/usr/bin/mkdir"; "--mode=0700"; "--"; path ] ->
            Directory.CreateDirectory(path) |> ignore
            let mode =
                if makeNextSshDirectoryUnsafe then
                    makeNextSshDirectoryUnsafe <- false
                    UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute ||| UnixFileMode.GroupRead ||| UnixFileMode.GroupWrite ||| UnixFileMode.GroupExecute ||| UnixFileMode.OtherRead ||| UnixFileMode.OtherWrite ||| UnixFileMode.OtherExecute
                else UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
            File.SetUnixFileMode(path, mode)
            match findUser userName with
            | Some row ->
                let fields = row.Split(':')
                setPathOwner path (UInt32.Parse(fields[2])) (UInt32.Parse(fields[3]))
                { ExitCode = 0; Stdout = ""; Stderr = "" }
            | None -> { ExitCode = 1; Stdout = ""; Stderr = "unknown user" }
        | "runuser", _
        | "/usr/sbin/runuser", _ -> { ExitCode = 0; Stdout = ""; Stderr = "" }
        | _ -> { ExitCode = 99; Stdout = ""; Stderr = "unexpected Users test command: " + executable }

    do
        for logicalPath in [ "/etc"; "/home" ] do
            let path = mappedPath logicalPath
            Directory.CreateDirectory(path) |> ignore
            File.SetUnixFileMode(path, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)
        File.WriteAllText(mappedPath "/etc/passwd", String.Join("\n", [| "root:x:0:0:root:/root:/bin/bash"; "debian:x:" + connectionUid.ToString() + ":" + connectionGid.ToString() + ":deployment:/home/debian:/bin/bash" |]) + "\n")
        File.WriteAllText(mappedPath "/etc/group", String.Join("\n", [| "root:x:0:"; "debian:x:" + connectionGid.ToString() + ":" |]) + "\n")
        File.WriteAllText(mappedPath "/etc/shadow", String.Join("\n", [| "root:!:19000:0:99999:7:::"; "debian:!:19000:0:99999:7:::" |]) + "\n")
        File.WriteAllText(
            mappedPath "/etc/login.defs",
            "UID_MIN 1000\nUID_MAX 60000\nSYS_UID_MIN 100\nSYS_UID_MAX 999\nGID_MIN 1000\nGID_MAX 60000\nSYS_GID_MIN 100\nSYS_GID_MAX 999\nUSERGROUPS_ENAB no\n")

    member _.Environment = TestSupport.fakeHostEnvironment root run (fun () -> DateTimeOffset.UnixEpoch)
    member _.Calls = calls
    member _.ConnectionUser = "debian"
    member _.ConnectionUid = connectionUid
    member _.MapPath(logicalPath: string) = mappedPath logicalPath
    member _.FailNextChpasswd(stderr: string) = failNextChpasswd <- Some stderr
    member _.FailNextUseradd() = failNextUseradd <- true
    member _.MakeNextSshDirectoryUnsafe() = makeNextSshDirectoryUnsafe <- true
    member _.EnableUserGroups() =
        let path = mappedPath "/etc/login.defs"
        File.WriteAllText(path, File.ReadAllText(path).Replace("USERGROUPS_ENAB no", "USERGROUPS_ENAB yes", StringComparison.Ordinal))
    member _.AddGroup(name: string, gid: int, members: string list) =
        let memberText = String.Join(",", members)
        writeRows "/etc/group" (groupRows () @ [ name + ":x:" + gid.ToString() + ":" + memberText ])
    member _.AddUser(name: string, uid: int, gid: int, description: string, home: string, shell: string, passwordHash: string) =
        writeRows "/etc/passwd" (accountRows () @ [ String.Join(":", [| name; "x"; uid.ToString(); gid.ToString(); description; home; shell |]) ])
        writeRows "/etc/shadow" (shadowRows () @ [ name + ":" + passwordHash + ":19000:0:99999:7:::" ])
    member _.SetShadowPassword(name: string, passwordHash: string) = changeShadow name passwordHash
    member _.CreateOwnedDirectory(logicalPath: string, uid: uint32, gid: uint32) =
        let path = mappedPath logicalPath
        Directory.CreateDirectory(path) |> ignore
        File.SetUnixFileMode(path, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)
        setPathOwner path uid gid
        path
    member _.SetPathOwner(path: string, uid: uint32, gid: uint32) = setPathOwner path uid gid
    member _.SupplementaryMemberships(userName: string) =
        groupRows ()
        |> List.choose (fun row ->
            let fields = row.Split(':')
            if fields[3].Split(',', StringSplitOptions.RemoveEmptyEntries) |> Array.contains userName then Some fields[0] else None)

[<RequireQualifiedAccess>]
module private UsersTestHelpers =
    let resourceId = "urn:pulumi:test::project::dorothy:host:Users::main"

    let stringValue (value: string) = JsonValue.Create(value) :> JsonNode
    let boolValue (value: bool) = JsonValue.Create(value) :> JsonNode
    let intValue (value: int) = JsonValue.Create(value) :> JsonNode
    let stringArray (values: seq<string>) =
        let result = JsonArray()
        for value in values do result.Add(stringValue value)
        result :> JsonNode

    let objectValue (fields: (string * JsonNode) list) =
        let result = JsonObject()
        for name, value in fields do result[name] <- value
        result :> JsonNode

    let user name (fields: (string * JsonNode) list) =
        objectValue (("name", stringValue name) :: fields)

    let adoptedUser name = user name [ "existing", stringValue "adopt" ]
    let group name (fields: (string * JsonNode) list) =
        objectValue (("name", stringValue name) :: fields)

    let supplementary mode names =
        objectValue [ "mode", stringValue mode; "names", stringArray names ]

    let runAsJsonWithConnectionUser resource operation connectionUser (host: UsersFakeHost) (groups: JsonNode list) (users: JsonNode list) =
        let groupArray = JsonArray()
        for group in groups do groupArray.Add(JsonNode.Parse(group.ToJsonString()))
        let userArray = JsonArray()
        for user in users do userArray.Add(JsonNode.Parse(user.ToJsonString()))
        let request = JsonObject()
        request["operation"] <- stringValue operation
        request["resourceId"] <- stringValue resource
        request["connectionUser"] <- stringValue connectionUser
        request["groups"] <- groupArray
        request["users"] <- userArray
        use document = JsonDocument.Parse(request.ToJsonString())
        Users.handle host.Environment document.RootElement

    let runAsJsonWithId resource operation (host: UsersFakeHost) (groups: JsonNode list) (users: JsonNode list) =
        runAsJsonWithConnectionUser resource operation host.ConnectionUser host groups users

    let runAsJson operation host groups users = runAsJsonWithId resourceId operation host groups users

    let actualUser (result: JsonNode) (name: string) =
        let actual = result.["actual"]
        actual.["users"].AsArray()
        |> Seq.find (fun value -> value.["name"].GetValue<string>() = name)

    let isInSync (result: JsonNode) = result["inSync"].GetValue<bool>()


    let ed25519Material seed =
        let wireString (bytes: byte array) =
            let length = BitConverter.GetBytes(uint32 bytes.Length)
            if BitConverter.IsLittleEndian then Array.Reverse length
            Array.concat [ length; bytes ]
        let algorithm = Encoding.UTF8.GetBytes("ssh-ed25519")
        let publicValue = Array.create 32 seed
        Array.concat [ wireString algorithm; wireString publicValue ] |> Convert.ToBase64String

    let key id material fields =
        objectValue ([ "id", stringValue id; "publicKey", stringValue("ssh-ed25519 " + material) ] @ fields)

    let authorizedKeys mode (keys: seq<JsonNode>) =
        let values = JsonArray()
        for value in keys do values.Add(value.DeepClone())
        objectValue [ "mode", stringValue mode; "keys", values ]

[<TestFixture>]
type UsersTests() =
    let makeHost () =
        let temporary = new TemporaryDirectory("dorothy-users-")
        temporary, UsersFakeHost(temporary.Path)

    [<Test>]
    member _.``Adopting an existing account does not apply creation defaults``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        host.AddGroup("legacy", 1200, [])
        host.AddUser("legacy", 1200, 1200, "Preserved account", "/nonexistent", "/bin/false", "!")

        let applied = UsersTestHelpers.runAsJson "apply" host [] [ UsersTestHelpers.adoptedUser "legacy" ]
        let actual = UsersTestHelpers.actualUser applied "legacy"

        Assert.That(UsersTestHelpers.isInSync applied, Is.True)
        Assert.That(actual["uid"].GetValue<int>(), Is.EqualTo(1200))
        Assert.That(actual["description"].GetValue<string>(), Is.EqualTo("Preserved account"))
        Assert.That(actual["home"].GetValue<string>(), Is.EqualTo("/nonexistent"))
        Assert.That(actual["shell"].GetValue<string>(), Is.EqualTo("/bin/false"))
        Assert.That(actual["locked"].GetValue<bool>(), Is.True)
        Assert.That(host.Calls |> Seq.exists (fun (name, _, _) -> name = "groupadd" || name = "useradd" || name = "usermod" || name = "chpasswd"), Is.False)

    [<Test>]
    member _.``Managed memberships preserve foreign memberships while exclusive replaces the list``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        host.AddGroup("legacy", 1200, [])
        host.AddGroup("coincidental", 1300, [ "legacy" ])
        host.AddGroup("foreign", 1301, [ "legacy" ])
        host.AddGroup("managed", 1302, [])
        host.AddGroup("exclusive", 1303, [])
        host.AddUser("legacy", 1200, 1200, "Legacy", "/nonexistent", "/bin/false", "!")

        let managed = UsersTestHelpers.user "legacy" [ "existing", UsersTestHelpers.stringValue "adopt"; "supplementaryGroups", UsersTestHelpers.supplementary "managed" [ "coincidental"; "managed" ] ]
        let first = UsersTestHelpers.runAsJson "apply" host [] [ managed ]
        Assert.That(UsersTestHelpers.isInSync first, Is.True)
        Assert.That(host.SupplementaryMemberships("legacy"), Is.EquivalentTo([ "coincidental"; "foreign"; "managed" ]))

        let updatedManaged = UsersTestHelpers.user "legacy" [ "existing", UsersTestHelpers.stringValue "adopt"; "supplementaryGroups", UsersTestHelpers.supplementary "managed" [ "coincidental" ] ]
        let second = UsersTestHelpers.runAsJson "apply" host [] [ updatedManaged ]
        Assert.That(UsersTestHelpers.isInSync second, Is.True)
        Assert.That(host.SupplementaryMemberships("legacy"), Is.EquivalentTo([ "coincidental"; "foreign" ]))

        let exclusive = UsersTestHelpers.user "legacy" [ "existing", UsersTestHelpers.stringValue "adopt"; "supplementaryGroups", UsersTestHelpers.supplementary "exclusive" [ "exclusive" ] ]
        let third = UsersTestHelpers.runAsJson "apply" host [] [ exclusive ]
        Assert.That(UsersTestHelpers.isInSync third, Is.True)
        Assert.That(host.SupplementaryMemberships("legacy"), Is.EquivalentTo([ "exclusive" ]))

    [<Test>]
    member _.``Deleting a resource retains its user and revokes only the membership it added``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        host.AddGroup("legacy", 1200, [])
        host.AddGroup("foreign", 1301, [ "legacy" ])
        host.AddGroup("owned", 1302, [])
        host.AddUser("legacy", 1200, 1200, "Retained", "/nonexistent", "/bin/false", "!")
        let declared = UsersTestHelpers.user "legacy" [ "existing", UsersTestHelpers.stringValue "adopt"; "supplementaryGroups", UsersTestHelpers.supplementary "managed" [ "owned" ] ]

        let applied = UsersTestHelpers.runAsJson "apply" host [] [ declared ]
        Assert.That(UsersTestHelpers.isInSync applied, Is.True)
        Assert.That(host.SupplementaryMemberships("legacy"), Is.EquivalentTo([ "foreign"; "owned" ]))

        let deleted = UsersTestHelpers.runAsJson "delete" host [] [ UsersTestHelpers.user "legacy" [ "existing", UsersTestHelpers.stringValue "adopt" ] ]
        let actual = UsersTestHelpers.actualUser deleted "legacy"
        Assert.That(deleted["exists"].GetValue<bool>(), Is.False)
        Assert.That(deleted["inSync"].GetValue<bool>(), Is.True)
        Assert.That(actual["exists"].GetValue<bool>(), Is.True)
        Assert.That(actual["description"].GetValue<string>(), Is.EqualTo("Retained"))
        Assert.That(host.SupplementaryMemberships("legacy"), Is.EquivalentTo([ "foreign" ]))

    [<Test>]
    member _.``An explicit absent declaration deletes only the account and leaves its home intact``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let effectiveUid = UsersTestNative.effectiveUserId ()
        let userUid = if effectiveUid = 0u then 1500u else effectiveUid
        if userUid < 1000u || userUid > 60000u then Assert.Ignore("The home-preservation fixture needs a non-root account UID in the configured human range.")
        let homePath = host.CreateOwnedDirectory("/home/preserved-home", userUid, 1500u)
        host.AddGroup("preserved", 1500, [])
        host.AddUser("preserved", int userUid, 1500, "Keep data", "/home/preserved-home", "/bin/false", "!")
        let home = host.MapPath("/home/preserved-home")
        Assert.That(Directory.Exists(home), Is.True)

        let absent = UsersTestHelpers.user "preserved" [ "state", UsersTestHelpers.stringValue "absent"; "existing", UsersTestHelpers.stringValue "adopt" ]
        let absentGroup = UsersTestHelpers.group "preserved" [ "state", UsersTestHelpers.stringValue "absent"; "existing", UsersTestHelpers.stringValue "adopt" ]
        let deleted = UsersTestHelpers.runAsJson "apply" host [ absentGroup ] [ absent ]

        Assert.That(deleted["inSync"].GetValue<bool>(), Is.True)
        let observed = UsersTestHelpers.actualUser deleted "preserved"
        Assert.That(observed.["exists"].GetValue<bool>(), Is.False)
        Assert.That(Directory.Exists(homePath), Is.True)
        Assert.That(File.ReadAllLines(host.MapPath("/etc/passwd")) |> Array.exists (fun row -> row.StartsWith("preserved:", StringComparison.Ordinal)), Is.False)

    [<Test>]
    member _.``userdel cannot implicitly remove an unadopted private group``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        host.EnableUserGroups()
        host.AddGroup("absent-example", 1500, [])
        host.AddUser("absent-example", 1500, 1500, "Private group owner", "/nonexistent", "/bin/false", "!")
        let absentUser =
            UsersTestHelpers.user "absent-example" [
                "state", UsersTestHelpers.stringValue "absent"
                "existing", UsersTestHelpers.stringValue "adopt" ]
        let unadoptedGroup = UsersTestHelpers.group "absent-example" [ "state", UsersTestHelpers.stringValue "absent" ]
        let denied () = UsersTestHelpers.runAsJson "apply" host [ unadoptedGroup ] [ absentUser ] |> ignore

        let error = Assert.Throws<Users.BackendError>(TestDelegate denied)
        Assert.That(error.Message, Does.Contain("unowned primary group"))
        Assert.That(File.ReadAllLines(host.MapPath("/etc/passwd")) |> Array.exists (fun row -> row.StartsWith("absent-example:", StringComparison.Ordinal)), Is.True)
        Assert.That(File.ReadAllLines(host.MapPath("/etc/group")) |> Array.exists (fun row -> row.StartsWith("absent-example:", StringComparison.Ordinal)), Is.True)
        Assert.That(host.Calls |> Seq.exists (fun (name, _, _) -> name = "userdel"), Is.False)

        let adoptedGroup =
            UsersTestHelpers.group "absent-example" [
                "state", UsersTestHelpers.stringValue "absent"
                "existing", UsersTestHelpers.stringValue "adopt" ]
        let applied = UsersTestHelpers.runAsJson "apply" host [ adoptedGroup ] [ absentUser ]
        Assert.That(UsersTestHelpers.isInSync applied, Is.True)
        Assert.That(File.ReadAllLines(host.MapPath("/etc/passwd")) |> Array.exists (fun row -> row.StartsWith("absent-example:", StringComparison.Ordinal)), Is.False)
        Assert.That(File.ReadAllLines(host.MapPath("/etc/group")) |> Array.exists (fun row -> row.StartsWith("absent-example:", StringComparison.Ordinal)), Is.False)

    [<Test>]
    member _.``The active connection account cannot be removed or mutated``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let absent = UsersTestHelpers.user host.ConnectionUser [ "state", UsersTestHelpers.stringValue "absent"; "existing", UsersTestHelpers.stringValue "adopt" ]
        let remove () = UsersTestHelpers.runAsJsonWithId "urn:test::connection-remove" "apply" host [] [ absent ] |> ignore
        let removeError = Assert.Throws<Users.BackendError>(TestDelegate remove)
        Assert.That(removeError.Message, Does.Contain("active connection user"))

        let mutation = UsersTestHelpers.user host.ConnectionUser [ "existing", UsersTestHelpers.stringValue "adopt"; "shell", UsersTestHelpers.stringValue "/bin/false" ]
        let mutate () = UsersTestHelpers.runAsJsonWithId "urn:test::connection-mutate" "apply" host [] [ mutation ] |> ignore
        let mutationError = Assert.Throws<Users.BackendError>(TestDelegate mutate)
        Assert.That(mutationError.Message, Does.Contain("active connection user"))
        Assert.That(host.Calls |> Seq.exists (fun (name, _, _) -> name = "userdel" || name = "pgrep" || name = "usermod"), Is.False)
        let activeGroup = UsersTestHelpers.group host.ConnectionUser [
            "state", UsersTestHelpers.stringValue "absent"
            "existing", UsersTestHelpers.stringValue "adopt" ]
        let removeGroup () = UsersTestHelpers.runAsJsonWithId "urn:test::connection-group-remove" "apply" host [ activeGroup ] [] |> ignore
        let groupError = Assert.Throws<Users.BackendError>(TestDelegate removeGroup)
        Assert.That(groupError.Message, Does.Contain("active connection user"))
        Assert.That(File.ReadAllLines(host.MapPath("/etc/group")) |> Array.exists (fun row -> row.StartsWith(host.ConnectionUser + ":", StringComparison.Ordinal)), Is.True)
        Assert.That(host.Calls |> Seq.exists (fun (name, _, _) -> name = "groupdel"), Is.False)

    [<Test>]
    member _.``The active connection account remains externally managed on delete``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let resource = "urn:test::managed-connection-user"
        let adopted = UsersTestHelpers.adoptedUser host.ConnectionUser

        let initiallyManaged =
            UsersTestHelpers.runAsJsonWithConnectionUser resource "apply" "root" host [] [ adopted ]
        Assert.That(UsersTestHelpers.isInSync initiallyManaged, Is.True)

        let callsBeforeDelete = host.Calls.Count
        let delete () =
            UsersTestHelpers.runAsJsonWithConnectionUser resource "delete" host.ConnectionUser host [] [] |> ignore
        let error = Assert.Throws<Users.BackendError>(TestDelegate delete)

        Assert.That(error.Message, Does.Contain("active connection user"))
        Assert.That(File.ReadAllLines(host.MapPath("/etc/passwd")) |> Array.exists (fun row -> row.StartsWith(host.ConnectionUser + ":", StringComparison.Ordinal)), Is.True)
        Assert.That(host.Calls |> Seq.skip callsBeforeDelete |> Seq.exists (fun (name, _, _) -> name = "gpasswd" || name = "userdel" || name = "usermod"), Is.False)

    [<Test>]
    member _.``A pending creation cannot repair defaults after becoming the connection account``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let resource = "urn:test::pending-connection-user"
        host.FailNextChpasswd("simulated interruption")
        let original =
            UsersTestHelpers.user "pending-admin" [
                "uid", UsersTestHelpers.intValue 2000
                "password",
                    UsersTestHelpers.objectValue [
                        "kind", UsersTestHelpers.stringValue "hash"
                        "hash", UsersTestHelpers.stringValue "$6$pending-salt$pending-password-hash"
                        "update", UsersTestHelpers.stringValue "always" ] ]
        let firstApply () = UsersTestHelpers.runAsJsonWithId resource "apply" host [] [ original ] |> ignore
        Assert.Throws<Users.BackendError>(TestDelegate firstApply) |> ignore

        let home = host.MapPath("/home/pending-admin")
        File.SetUnixFileMode(
            home,
            UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
            ||| UnixFileMode.GroupRead ||| UnixFileMode.GroupExecute
            ||| UnixFileMode.OtherRead ||| UnixFileMode.OtherExecute)
        let callsBeforeRetry = host.Calls.Count
        let retry () =
            UsersTestHelpers.runAsJsonWithConnectionUser resource "apply" "pending-admin" host [] [ UsersTestHelpers.user "pending-admin" [] ] |> ignore
        let error = Assert.Throws<Users.BackendError>(TestDelegate retry)

        Assert.That(error.Message, Does.Contain("active connection user"))
        Assert.That(File.GetUnixFileMode(home), Is.EqualTo(
            UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
            ||| UnixFileMode.GroupRead ||| UnixFileMode.GroupExecute
            ||| UnixFileMode.OtherRead ||| UnixFileMode.OtherExecute))
        Assert.That(
            host.Calls
            |> Seq.skip callsBeforeRetry
            |> Seq.exists (fun (name, _, _) -> name = "usermod" || name = "passwd" || name = "chpasswd"),
            Is.False)

    [<Test>]
    member _.``Reserved and already assigned account IDs are rejected before identity creation``() =
        let temporary, host = makeHost ()
        use _temporary = temporary

        let zeroUid = UsersTestHelpers.user "zeroalias" [ "uid", UsersTestHelpers.intValue 0 ]
        let zeroUidAction () = UsersTestHelpers.runAsJson "apply" host [] [ zeroUid ] |> ignore
        Assert.Throws<Users.BackendError>(TestDelegate zeroUidAction) |> ignore

        let usedUid = UsersTestHelpers.user "uidcollision" [ "uid", UsersTestHelpers.intValue host.ConnectionUid ]
        let usedUidAction () = UsersTestHelpers.runAsJson "apply" host [] [ usedUid ] |> ignore
        Assert.Throws<Users.BackendError>(TestDelegate usedUidAction) |> ignore

        let usedGid = UsersTestHelpers.group "gidcollision" [ "gid", UsersTestHelpers.intValue host.ConnectionUid ]
        let usedGidAction () = UsersTestHelpers.runAsJson "apply" host [ usedGid ] [] |> ignore
        Assert.Throws<Users.BackendError>(TestDelegate usedGidAction) |> ignore

        Assert.That(host.Calls |> Seq.exists (fun (name, _, _) -> name = "groupadd" || name = "useradd"), Is.False)

    [<Test>]
    member _.``Pending account creation reserves its numeric UID for other resources``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        host.FailNextUseradd()
        let interrupted = UsersTestHelpers.user "pendingowner" [ "uid", UsersTestHelpers.intValue 2000 ]
        let initialApply () = UsersTestHelpers.runAsJsonWithId "urn:test::pending-owner" "apply" host [] [ interrupted ] |> ignore

        Assert.Throws<Users.BackendError>(TestDelegate initialApply) |> ignore
        Assert.That(File.ReadAllLines(host.MapPath("/etc/passwd")) |> Array.exists (fun row -> row.StartsWith("pendingowner:", StringComparison.Ordinal)), Is.False)
        Assert.That(File.ReadAllLines(host.MapPath("/etc/group")) |> Array.exists (fun row -> row.StartsWith("pendingowner:", StringComparison.Ordinal)), Is.True)

        let callsBeforeCollision = host.Calls.Count
        let collision =
            UsersTestHelpers.user "numeric-collision" [
                "uid", UsersTestHelpers.intValue 2000
                "primaryGroup", UsersTestHelpers.objectValue [ "kind", UsersTestHelpers.stringValue "existing"; "name", UsersTestHelpers.stringValue "debian" ] ]
        let collide () = UsersTestHelpers.runAsJsonWithId "urn:test::other-owner" "apply" host [] [ collision ] |> ignore
        Assert.Throws<Users.BackendError>(TestDelegate collide) |> ignore
        Assert.That(
            host.Calls
            |> Seq.skip callsBeforeCollision
            |> Seq.exists (fun (name, _, _) -> name = "useradd" || name = "groupadd"),
            Is.False)

    [<Test>]
    member _.``New system users receive locked no-home nologin defaults``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let systemUser = UsersTestHelpers.user "appworker" [ "kind", UsersTestHelpers.stringValue "system" ]

        let applied = UsersTestHelpers.runAsJson "apply" host [] [ systemUser ]
        let actual = UsersTestHelpers.actualUser applied "appworker"
        let add = host.Calls |> Seq.find (fun (name, _, _) -> name = "useradd") |> fun (_, args, _) -> args

        Assert.That(UsersTestHelpers.isInSync applied, Is.True)
        Assert.That(actual["uid"].GetValue<int>(), Is.InRange(100, 999))
        Assert.That(actual["gid"].GetValue<int>(), Is.EqualTo(actual["uid"].GetValue<int>()))
        Assert.That(actual["home"].GetValue<string>(), Is.EqualTo("/nonexistent"))
        Assert.That(actual["shell"].GetValue<string>(), Is.EqualTo("/usr/sbin/nologin"))
        Assert.That(actual["locked"].GetValue<bool>(), Is.True)
        Assert.That(add, Does.Contain("--system"))
        Assert.That(add, Does.Contain("/nonexistent"))
        Assert.That(add, Does.Contain("/usr/sbin/nologin"))
        Assert.That(add, Does.Contain("--no-create-home"))

    [<Test>]
    member _.``Password hashes stay private and externally changed hashes report drift``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        host.AddGroup("legacy", 1200, [])
        host.AddUser("legacy", 1200, 1200, "Legacy", "/nonexistent", "/bin/false", "!")
        let hash = "$6$private-test-salt$actualHashMustNeverBeReturned"
        let userWithHash () =
            UsersTestHelpers.user "legacy" [
                "existing", UsersTestHelpers.stringValue "adopt"
                "password", UsersTestHelpers.objectValue [ "kind", UsersTestHelpers.stringValue "hash"; "hash", UsersTestHelpers.stringValue hash; "update", UsersTestHelpers.stringValue "always" ] ]

        let applied = UsersTestHelpers.runAsJson "apply" host [] [ userWithHash () ]
        let serialized = applied.ToJsonString()
        Assert.That(UsersTestHelpers.isInSync applied, Is.True)
        Assert.That(serialized.Contains(hash, StringComparison.Ordinal), Is.False)

        let driftedHash = "$6$external-salt$externallyChangedValue"
        host.SetShadowPassword("legacy", driftedHash)
        let read = UsersTestHelpers.runAsJson "read" host [] [ userWithHash () ]
        Assert.That(UsersTestHelpers.isInSync read, Is.False)
        Assert.That(read.ToJsonString().Contains(hash, StringComparison.Ordinal), Is.False)
        Assert.That(read.ToJsonString().Contains(driftedHash, StringComparison.Ordinal), Is.False)
        let actual = UsersTestHelpers.actualUser read "legacy"
        Assert.That(actual.AsObject().ContainsKey("passwordHash"), Is.False)

        let failureTemporary, failingHost = makeHost ()
        use _failureTemporary = failureTemporary
        failingHost.AddGroup("legacy", 1200, [])
        failingHost.AddUser("legacy", 1200, 1200, "Legacy", "/nonexistent", "/bin/false", "!")
        failingHost.FailNextChpasswd("simulated failure mentioning " + hash)
        let failApply () = UsersTestHelpers.runAsJson "apply" failingHost [] [ userWithHash () ] |> ignore
        let error = Assert.Throws<Users.BackendError>(TestDelegate failApply)
        Assert.That(error.Message.Contains(hash, StringComparison.Ordinal), Is.False)

    [<Test>]
    member _.``Rejects password hash whitespace and command-shaped account names``() =
        let temporary, host = makeHost ()
        use _temporary = temporary
        let hostileHash = "$6$secret material"
        let malformed =
            UsersTestHelpers.user "legacy" [
                "existing", UsersTestHelpers.stringValue "adopt"
                "password", UsersTestHelpers.objectValue [ "kind", UsersTestHelpers.stringValue "hash"; "hash", UsersTestHelpers.stringValue hostileHash ] ]
        let malformedAction () = UsersTestHelpers.runAsJson "apply" host [] [ malformed ] |> ignore
        let hashError = Assert.Throws<Users.BackendError>(TestDelegate malformedAction)
        Assert.That(hashError.Message.Contains(hostileHash, StringComparison.Ordinal), Is.False)

        let malicious = UsersTestHelpers.user "legacy;touch /tmp/not-allowed" []
        let identityAction () = UsersTestHelpers.runAsJson "apply" host [] [ malicious ] |> ignore
        Assert.Throws<Users.BackendError>(TestDelegate identityAction) |> ignore
        Assert.That(host.Calls.Count, Is.EqualTo(0))

    [<Test>]
    member _.``Managed key ownership preserves coincidental credentials and exclusive deletion does not resurrect them``() =
        if UsersTestNative.effectiveUserId () <> 0u then Assert.Ignore("Authorized-key ownership regression requires root to create user-owned key fixtures.")
        let temporary, host = makeHost ()
        use _temporary = temporary
        host.AddGroup("keyoperator", 1600, [])
        host.AddUser("keyoperator", 1600, 1600, "Key operator", "/home/keyoperator", "/bin/bash", "!")
        let home = host.CreateOwnedDirectory("/home/keyoperator", 1600u, 1600u)
        let sshDirectory = Path.Combine(home, ".ssh")
        Directory.CreateDirectory(sshDirectory) |> ignore
        File.SetUnixFileMode(sshDirectory, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)
        host.SetPathOwner(sshDirectory, 1600u, 1600u)

        let coincidentalMaterial = UsersTestHelpers.ed25519Material 0x11uy
        let foreignMaterial = UsersTestHelpers.ed25519Material 0x22uy
        let managedMaterial = UsersTestHelpers.ed25519Material 0x33uy
        let exclusiveMaterial = UsersTestHelpers.ed25519Material 0x44uy
        let coincidentalLine = "ssh-ed25519 " + coincidentalMaterial + " coincidental credential"
        let foreignLine = "ssh-ed25519 " + foreignMaterial + " foreign credential"
        let authorizedKeysPath = Path.Combine(sshDirectory, "authorized_keys")
        let initialLines = [ foreignLine; coincidentalLine ]
        File.WriteAllText(authorizedKeysPath, String.Join("\n", initialLines) + "\n")
        File.SetUnixFileMode(authorizedKeysPath, UnixFileMode.UserRead ||| UnixFileMode.UserWrite)
        host.SetPathOwner(authorizedKeysPath, 1600u, 1600u)

        let managedCommand = "/bin/echo \"quoted\"\\path"
        let managedLine =
            "restrict,pty,no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc,from=\"host one,203.0.113.8\",command=\"/bin/echo \\\"quoted\\\"\\\\path\",permitopen=\"example.test:22\",permitopen=\"[::1]:2222\" ssh-ed25519 "
            + managedMaterial
            + " managed-command"
        let coincidentalKey = UsersTestHelpers.key "preexisting" coincidentalMaterial [ "comment", UsersTestHelpers.stringValue "coincidental credential" ]
        let restrictedKey =
            UsersTestHelpers.key "managed-command" managedMaterial [
                "comment", UsersTestHelpers.stringValue "managed-command"
                "restrict", UsersTestHelpers.boolValue true
                "allowPty", UsersTestHelpers.boolValue true
                "allowAgentForwarding", UsersTestHelpers.boolValue false
                "allowPortForwarding", UsersTestHelpers.boolValue false
                "allowX11Forwarding", UsersTestHelpers.boolValue false
                "allowUserRc", UsersTestHelpers.boolValue false
                "allowFrom", UsersTestHelpers.stringArray [ "host one"; "203.0.113.8" ]
                "command", UsersTestHelpers.stringValue managedCommand
                "permitOpen", UsersTestHelpers.stringArray [ "example.test:22"; "[::1]:2222" ] ]
        let managedUser () =
            UsersTestHelpers.user "keyoperator" [
                "existing", UsersTestHelpers.stringValue "adopt"
                "authorizedKeys", UsersTestHelpers.authorizedKeys "managed" [ coincidentalKey; restrictedKey ] ]

        let managedApply = UsersTestHelpers.runAsJsonWithId "urn:test::managed-keys" "apply" host [] [ managedUser () ]
        Assert.That(UsersTestHelpers.isInSync managedApply, Is.True)
        Assert.That(File.ReadAllLines(authorizedKeysPath), Is.EquivalentTo([| foreignLine; coincidentalLine; managedLine |]))

        UsersTestHelpers.runAsJsonWithId "urn:test::managed-keys" "delete" host [] [ managedUser () ] |> ignore
        Assert.That(File.ReadAllLines(authorizedKeysPath), Is.EquivalentTo([| foreignLine; coincidentalLine |]))

        let exclusiveLine = "ssh-ed25519 " + exclusiveMaterial + " exclusive credential"
        let exclusiveKey = UsersTestHelpers.key "exclusive" exclusiveMaterial [ "comment", UsersTestHelpers.stringValue "exclusive credential" ]
        let exclusiveUser () =
            UsersTestHelpers.user "keyoperator" [
                "existing", UsersTestHelpers.stringValue "adopt"
                "authorizedKeys", UsersTestHelpers.authorizedKeys "exclusive" [ exclusiveKey ] ]
        let exclusiveApply = UsersTestHelpers.runAsJsonWithId "urn:test::exclusive-keys" "apply" host [] [ exclusiveUser () ]
        Assert.That(UsersTestHelpers.isInSync exclusiveApply, Is.True)
        Assert.That(File.ReadAllLines(authorizedKeysPath), Is.EquivalentTo([| exclusiveLine |]))

        File.WriteAllText(authorizedKeysPath, foreignLine + "\n")
        let drifted = UsersTestHelpers.runAsJsonWithId "urn:test::exclusive-keys" "read" host [] [ exclusiveUser () ]
        Assert.That(UsersTestHelpers.isInSync drifted, Is.False)
        Assert.That(File.ReadAllLines(authorizedKeysPath), Is.EquivalentTo([| foreignLine |]))
        let repaired = UsersTestHelpers.runAsJsonWithId "urn:test::exclusive-keys" "apply" host [] [ exclusiveUser () ]
        Assert.That(UsersTestHelpers.isInSync repaired, Is.True)
        Assert.That(File.ReadAllLines(authorizedKeysPath), Is.EquivalentTo([| exclusiveLine |]))

        UsersTestHelpers.runAsJsonWithId "urn:test::exclusive-keys" "delete" host [] [ exclusiveUser () ] |> ignore
        Assert.That(File.ReadAllLines(authorizedKeysPath), Is.Empty)
        Assert.That(File.ReadAllText(authorizedKeysPath).Contains(foreignLine, StringComparison.Ordinal), Is.False)
        Assert.That(File.ReadAllText(authorizedKeysPath).Contains(coincidentalLine, StringComparison.Ordinal), Is.False)
        Assert.That(File.ReadAllText(authorizedKeysPath).Contains(exclusiveLine, StringComparison.Ordinal), Is.False)

    [<Test>]
    member _.``Retries a pending authorized-key intent after repairing a failed owned-directory creation``() =
        if UsersTestNative.effectiveUserId () <> 0u then Assert.Ignore("Authorized-key recovery regression requires root to create user-owned key fixtures.")
        let temporary, host = makeHost ()
        use _temporary = temporary
        host.AddGroup("pendingkey", 1700, [])
        host.AddUser("pendingkey", 1700, 1700, "Pending key", "/home/pendingkey", "/bin/bash", "!")
        let home = host.CreateOwnedDirectory("/home/pendingkey", 1700u, 1700u)
        let material = UsersTestHelpers.ed25519Material 0x55uy
        let line = "ssh-ed25519 " + material + " retry-safe"
        let key = UsersTestHelpers.key "retry-safe" material [ "comment", UsersTestHelpers.stringValue "retry-safe" ]
        let declared () =
            UsersTestHelpers.user "pendingkey" [
                "existing", UsersTestHelpers.stringValue "adopt"
                "authorizedKeys", UsersTestHelpers.authorizedKeys "managed" [ key ] ]
        let resource = "urn:test::pending-key-recovery"
        let sshDirectory = Path.Combine(home, ".ssh")
        let authorizedKeysPath = Path.Combine(sshDirectory, "authorized_keys")

        host.MakeNextSshDirectoryUnsafe()
        let interruptedApply () = UsersTestHelpers.runAsJsonWithId resource "apply" host [] [ declared () ] |> ignore
        Assert.Throws<Users.BackendError>(TestDelegate interruptedApply) |> ignore
        Assert.That(Directory.Exists(sshDirectory), Is.True)
        Assert.That(File.Exists(authorizedKeysPath), Is.False)
        let unsafeMode =
            UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute
            ||| UnixFileMode.GroupRead ||| UnixFileMode.GroupWrite ||| UnixFileMode.GroupExecute
            ||| UnixFileMode.OtherRead ||| UnixFileMode.OtherWrite ||| UnixFileMode.OtherExecute
        Assert.That(File.GetUnixFileMode(sshDirectory), Is.EqualTo(unsafeMode))

        File.SetUnixFileMode(sshDirectory, UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)
        host.SetPathOwner(sshDirectory, 1700u, 1700u)
        let retried = UsersTestHelpers.runAsJsonWithId resource "apply" host [] [ declared () ]
        Assert.That(UsersTestHelpers.isInSync retried, Is.True)
        Assert.That(File.ReadAllLines(authorizedKeysPath), Is.EquivalentTo([| line |]))

        UsersTestHelpers.runAsJsonWithId resource "delete" host [] [ declared () ] |> ignore
        Assert.That(File.ReadAllLines(authorizedKeysPath), Is.Empty)
