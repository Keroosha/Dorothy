namespace Dorothy.Tests

open System
open System.Collections.Generic
open System.IO
open System.Globalization
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.Json.Nodes
open Dorothy.HostHelper
open NUnit.Framework

[<TestFixture>]
type UfwBackendTests() =
    let markerHex (marker: string) = Convert.ToHexString(Encoding.UTF8.GetBytes marker).ToLowerInvariant()

    let makeBlock family marker action port command =
        let address = if family = "4" then "0.0.0.0/0" else "::/0"
        let tuple = String.concat " " [ action; "tcp"; port; address; "any"; address; "in" ]
        let header = "### tuple ### " + tuple + " comment=" + markerHex marker
        { Family = family
          Marker = Some marker
          Tuple = tuple
          Canonical = action + " " + port + "/tcp"
          Commands = [| command |]
          Lines = [| header; command |] }

    let makeApplicationBlock marker =
        let tuple = "allow tcp any 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in"
        let command = "-A ufw-user-input -m comment --comment 'dapp_OpenSSH' -p tcp --dport 22 -j ACCEPT"
        { Family = "4"
          Marker = Some marker
          Tuple = tuple
          Canonical = "allow OpenSSH"
          Commands = [| command |]
          Lines = [| "### tuple ### " + tuple + " comment=" + markerHex marker; command |] }

    let marker (owner: string) (index: int) = Ufw.ownerMarkerPrefix owner + "r" + index.ToString("D8", CultureInfo.InvariantCulture) + ":" + String.replicate 64 "a"

    let runtimeTable family active partial rules allRules policies chains =
        { Family = family
          Active = active
          Partial = partial
          Related = true
          ReachableChains = Set.empty
          Rules = rules
          AllRules = allRules
          Policies = policies
          Chains = chains }

    let digest (text: string) =
        SHA256.HashData(Encoding.UTF8.GetBytes text)
        |> Convert.ToHexString
        |> fun value -> value.ToLowerInvariant()

    [<Test>]
    member _.``Raw route limit and quoted profile arguments pass the security boundary``() =
        // Arrange
        let routeRule = [ "route"; "limit"; "from"; "any"; "to"; "any"; "port"; "22" ]
        let profileRule = [ "allow"; "from"; "any"; "app"; "Example Profile" ]

        // Act
        let routeActual = Ufw.validateRuleTokens 0 routeRule
        let profileActual = Ufw.validateRuleTokens 1 profileRule

        // Assert
        Assert.That(routeActual, Is.EqualTo(box routeRule))
        Assert.That(profileActual, Is.EqualTo(box profileRule))

    [<Test>]
    member _.``Raw comments management commands options and shell operators are rejected``() =
        // Arrange
        let invalidRules =
            [ [ "allow"; "comment"; "mine" ]
              [ "allow"; "COMMENT"; "mine" ]
              [ "reset" ]
              [ "allow"; "--force" ]
              [ "allow"; "to"; "any;"; "port"; "22" ]
              [ "allow"; "to"; "any"; "port"; "22\n" ] ]

        // Act
        let actions = invalidRules |> List.map (fun rule -> TestDelegate(fun () -> Ufw.validateRuleTokens 0 rule |> ignore))

        // Assert
        for action in actions do Assert.Throws<Ufw.BackendError>(action) |> ignore

    [<Test>]
    member _.``Enable guard requires an unrestricted dual-stack SSH rule and outbound allow``() =
        // Arrange
        let v4 = makeBlock "4" "owner:v4" "allow" "22" "-A ufw-user-input -p tcp --dport 22 -j ACCEPT"
        let v6 = makeBlock "6" "owner:v6" "allow" "22" "-A ufw6-user-input -p tcp --dport 22 -j ACCEPT"
        let desired = [ { v4 with Canonical = "allow 22/tcp" }, [| v4; v6 |] ]
        let restrictedV4 = { v4 with Commands = [| "-A ufw-user-input -i eth0 -p tcp --dport 22 -j ACCEPT" |] }
        let restricted = [ { v4 with Canonical = "allow in on eth0 22/tcp" }, [| restrictedV4; v6 |] ]

        // Act
        Ufw.validateEnableGuard desired 22 true "allow"
        let wrongDefault = TestDelegate(fun () -> Ufw.validateEnableGuard desired 22 true "deny")
        let wrongRule = TestDelegate(fun () -> Ufw.validateEnableGuard restricted 22 true "allow")

        // Assert
        Assert.Throws<Ufw.BackendError>(wrongDefault) |> ignore
        Assert.Throws<Ufw.BackendError>(wrongRule) |> ignore

    [<Test>]
    member _.``Missing native UFW is reported at the command boundary``() =
        // Arrange
        let mutable calls = 0
        let run _ _ _ =
            calls <- calls + 1
            { ExitCode = 127; Stdout = ""; Stderr = "not found" }
        let environment = TestSupport.fakeHostEnvironment "/" run (fun () -> DateTimeOffset.UnixEpoch)

        // Act
        let action = TestDelegate(fun () -> Ufw.ensureNativeUfw environment)

        // Assert
        Assert.Throws<Ufw.BackendError>(action) |> ignore
        Assert.That(calls, Is.EqualTo(1))

    [<Test>]
    member _.``Owner marker hashes retain legacy simple and quoted-profile vectors``() =
        // Arrange
        let owner = "resource-a"
        let prefix = "keroosha-iac:be49bedc2c4062a4416c89eeca4979c676cba8e127108186c20afad636c71854:"

        // Act
        let actualPrefix = Ufw.ownerMarkerPrefix owner
        let simple = Ufw.makeOwnerMarker "resource-a" 0 "both" "allow 22/tcp"
        let profile = Ufw.makeOwnerMarker "resource-a" 0 "both" "allow 'WWW Full'"

        // Assert
        Assert.That(actualPrefix, Is.EqualTo(prefix))
        Assert.That(simple, Is.EqualTo(prefix + "r00000000:202fa267334ff53d3e5e4c78e4b0c00f044160c832a8b0b3f0c6a5e14ba28a1f"))
        Assert.That(profile, Is.EqualTo(prefix + "r00000000:68a312804c75eb25de6461619bce26eb9ca18d649dc480dc38f601f79e467995"))
        Assert.That(Ufw.ownerMarkerPrefix owner, Is.EqualTo(Ufw.ownerMarkerPrefix owner))
        Assert.That(Ufw.ownerMarkerPrefix "resource-b", Is.Not.EqualTo(prefix))

    [<Test>]
    member _.``Native profile expansion compares concrete ports without action or app-label ownership``() =
        // Arrange
        let profile = makeApplicationBlock "owner:profile"
        let unmanaged = makeBlock "4" "operator:rule" "deny" "22" "-A ufw-user-input -p tcp -m tcp --dport 22 -j DROP"

        // Act
        let profileKey = Ufw.semanticKey profile
        let unmanagedKey = Ufw.semanticKey unmanaged

        // Assert
        Assert.That(profileKey, Is.EqualTo(unmanagedKey))

    [<Test>]
    member _.``Owner marker cannot conceal changed native rule content``() =
        // Arrange
        let ownedMarker = marker "resource-a" 0
        let expected = makeBlock "4" ownedMarker "allow" "22" "-A ufw-user-input -p tcp --dport 22 -j ACCEPT"
        let actual = makeBlock "4" ownedMarker "deny" "22" "-A ufw-user-input -p tcp --dport 22 -j DROP"

        // Act
        let matches = Ufw.ownerRuleBlocksMatch (Ufw.ownerMarkerPrefix "resource-a") [| actual |] [| expected |]

        // Assert
        Assert.That(matches, Is.False)

    [<Test>]
    member _.``Owned rules interleaved with unmanaged rules are not a converged block``() =
        // Arrange
        let ownedMarker = marker "resource-a" 0
        let owned = makeBlock "4" ownedMarker "allow" "22" "-A ufw-user-input -p tcp --dport 22 -j ACCEPT"
        let unmanaged = makeBlock "4" "operator:rule" "deny" "80" "-A ufw-user-input -p tcp --dport 80 -j DROP"
        let actual = [| owned; unmanaged |]

        // Act
        let matches = Ufw.ownerRuleBlocksMatch (Ufw.ownerMarkerPrefix "resource-a") actual [| owned |]

        // Assert
        Assert.That(matches, Is.False)

    [<Test>]
    member _.``No-END native seeds accept rule updates and preserve helper chains``() =
        // Arrange
        let owner = "resource-a"
        let prefix = Ufw.ownerMarkerPrefix owner
        let ownedMarker = marker owner 0
        let command = "-A ufw-user-input -p tcp --dport 22 -j ACCEPT"
        let owned = makeBlock "4" ownedMarker "allow" "22" command
        let helper1 = "-A ufw-user-limit -m limit --limit 3/minute -j LOG --log-prefix \"[UFW LIMIT BLOCK] \""
        let helper2 = "-A ufw-user-limit -j REJECT"
        let seed =
            "*filter\n:ufw-user-input - [0:0]\n:ufw-user-output - [0:0]\n:ufw-user-forward - [0:0]\n"
            + ":ufw-user-limit - [0:0]\n:ufw-user-limit-accept - [0:0]\n### RULES ###\n"
            + helper1 + "\n" + helper2 + "\n-A ufw-user-limit-accept -j ACCEPT\nCOMMIT\n"

        // Act
        let created, createdChanged = Ufw.reconcileOwnedRuleBlocks prefix "4" Map.empty [| owned |] seed
        let expected = Map.ofList [ ownedMarker, [| command |] ]
        let repeated, repeatedChanged = Ufw.reconcileOwnedRuleBlocks prefix "4" expected [| owned |] created
        let deleted, deletedChanged = Ufw.reconcileOwnedRuleBlocks prefix "4" expected [||] repeated

        // Assert
        Assert.That(Ufw.ruleSection (seed.Split([| "\n" |], StringSplitOptions.None)), Is.EqualTo((6, 10)))
        Assert.That(createdChanged, Is.True)
        Assert.That(created.Contains("### END RULES ###"), Is.False)
        Assert.That(created.Contains(markerHex ownedMarker), Is.True)
        Assert.That(created.IndexOf(markerHex ownedMarker, StringComparison.Ordinal), Is.LessThan(created.IndexOf(helper1, StringComparison.Ordinal)))
        Assert.That(created.Split([| helper1 |], StringSplitOptions.None).Length - 1, Is.EqualTo(1))
        Assert.That(created.Split([| helper2 |], StringSplitOptions.None).Length - 1, Is.EqualTo(1))
        Assert.That(repeatedChanged, Is.False)
        Assert.That(repeated, Is.EqualTo(created))
        Assert.That(deletedChanged, Is.True)
        Assert.That(deleted, Is.EqualTo(seed))

    [<Test>]
    member _.``Malformed native table section boundaries fail closed``() =
        // Arrange
        let valid = "*filter\n### RULES ###\nCOMMIT\n"
        let malformed =
            [ "missing table", "### RULES ###\nCOMMIT\n"
              "duplicate table", "*filter\n*filter\n### RULES ###\nCOMMIT\n"
              "other table", "*filter\n*nat\n### RULES ###\nCOMMIT\n"
              "missing commit", "*filter\n### RULES ###\n"
              "duplicate commit", "*filter\n### RULES ###\nCOMMIT\nCOMMIT\n"
              "commit before rules", "*filter\nCOMMIT\n### RULES ###\n"
              "missing start", "*filter\nCOMMIT\n"
              "duplicate start", "*filter\n### RULES ###\n### RULES ###\nCOMMIT\n"
              "close before start", "*filter\n### END RULES ###\n### RULES ###\nCOMMIT\n"
              "duplicate close", "*filter\n### RULES ###\n### END RULES ###\n### END RULES ###\nCOMMIT\n"
              "close after commit", "*filter\n### RULES ###\nCOMMIT\n### END RULES ###\n" ]

        // Act
        let actions = malformed |> List.map (fun (_, text) -> TestDelegate(fun () -> Ufw.ruleSection (text.Split([| "\n" |], StringSplitOptions.None)) |> ignore))

        // Assert
        Assert.That(Ufw.ruleSection (valid.Split([| "\n" |], StringSplitOptions.None)), Is.EqualTo((1, 2)))
        for action in actions do Assert.Throws<Ufw.BackendError>(action) |> ignore

    [<Test>]
    member _.``Semantic collisions ignore verdict and application label but retain ports``() =
        // Arrange
        let profile = makeApplicationBlock "desired:profile"
        let unmanaged = makeBlock "4" "operator:rule" "deny" "22" "-A ufw-user-input -p tcp -m tcp --dport 22 -j DROP"
        let differentPort = makeBlock "4" "operator:rule" "deny" "18445" "-A ufw-user-input -p tcp -m tcp --dport 18445 -j DROP"
        let allow = makeBlock "4" "desired:allow" "allow" "22" "-A ufw-user-input -p tcp --dport 22 -j ACCEPT"
        let limit = makeBlock "4" "operator:limit" "limit" "22" "-A ufw-user-input -p tcp --dport 22 -m recent --set -j ufw-user-limit"
        let ownedDuplicate = { unmanaged with Marker = Some(Ufw.ownerMarkerPrefix "resource-a" + "r00000000:" + String.replicate 64 "b") }

        // Act
        let profileKey = Ufw.semanticKey profile
        let unmanagedKey = Ufw.semanticKey unmanaged
        let collision = Ufw.hasUnmanagedSemanticCollision [| profile |] [| unmanaged |] (Ufw.ownerMarkerPrefix "resource-a")
        let differentPortIsNotCollision = Ufw.hasUnmanagedSemanticCollision [| profile |] [| differentPort |] (Ufw.ownerMarkerPrefix "resource-a")
        let ownedIsNotUnmanaged = Ufw.hasUnmanagedSemanticCollision [| profile |] [| ownedDuplicate |] (Ufw.ownerMarkerPrefix "resource-a")
        let limitIsCollision = Ufw.hasUnmanagedSemanticCollision [| allow |] [| limit |] (Ufw.ownerMarkerPrefix "resource-a")

        // Assert
        Assert.That(profileKey, Is.EqualTo(unmanagedKey))
        Assert.That(collision, Is.True)
        Assert.That(ownedIsNotUnmanaged, Is.False)
        Assert.That(differentPortIsNotCollision, Is.False)
        Assert.That(limitIsCollision, Is.True)

    [<Test>]
    member _.``Delete removes only owned records while retaining notes and unmanaged order``() =
        // Arrange
        let owner = "resource-a"
        let ownedMarker = marker owner 0
        let unmanagedMarker = "operator:unmanaged"
        let owned = makeBlock "4" ownedMarker "allow" "22" "-A ufw-user-input -p tcp --dport 22 -j ACCEPT"
        let unmanaged = makeBlock "4" unmanagedMarker "deny" "80" "-A ufw-user-input -p tcp --dport 80 -j DROP"
        let note = "# operator note retained"
        let contents =
            "*filter\n### RULES ###\n"
            + owned.Lines[0] + "\n" + owned.Commands[0] + "\n" + note + "\n"
            + unmanaged.Lines[0] + "\n" + unmanaged.Commands[0] + "\n\n### END RULES ###\nCOMMIT\n"
        let expected = Map.ofList [ ownedMarker, owned.Commands ]

        // Act
        let actual, changed = Ufw.reconcileOwnedRuleBlocks (Ufw.ownerMarkerPrefix owner) "4" expected [||] contents

        // Assert
        Assert.That(changed, Is.True)
        Assert.That(actual.Contains(markerHex ownedMarker), Is.False)
        Assert.That(actual.Contains(note), Is.True)
        Assert.That(actual.Contains(unmanaged.Lines[0] + "\n" + unmanaged.Commands[0]), Is.True)
        Assert.That(actual.IndexOf(note, StringComparison.Ordinal), Is.LessThan(actual.IndexOf(unmanaged.Lines[0], StringComparison.Ordinal)))

    [<Test>]
    member _.``Unattributable raw commands inside an owned record fail closed``() =
        // Arrange
        let owner = "resource-a"
        let ownedMarker = marker owner 0
        let owned = makeBlock "4" ownedMarker "allow" "22" "-A ufw-user-input -p tcp --dport 22 -j ACCEPT"
        let raw = "-A ufw-user-input -p udp --dport 53 -j ACCEPT"
        let contents = "*filter\n### RULES ###\n" + owned.Lines[0] + "\n" + owned.Commands[0] + "\n" + raw + "\n### END RULES ###\nCOMMIT\n"
        let expected = Map.ofList [ ownedMarker, owned.Commands ]

        // Act
        let action = TestDelegate(fun () -> Ufw.reconcileOwnedRuleBlocks (Ufw.ownerMarkerPrefix owner) "4" expected [||] contents |> ignore)

        // Assert
        Assert.Throws<Ufw.BackendError>(action) |> ignore
        Assert.That(contents.Contains(raw), Is.True)

    [<Test>]
    member _.``Native startup is followed by a user-rule synchronization reload``() =
        // Arrange
        let calls = ResizeArray<string * string list * string option>()
        let run executable arguments input =
            calls.Add((executable, arguments, input))
            { ExitCode = 0; Stdout = ""; Stderr = "" }
        let environment = TestSupport.fakeHostEnvironment "/" run (fun () -> DateTimeOffset.UnixEpoch)

        // Act
        Ufw.enableAndReload environment

        // Assert
        Assert.That(calls.ToArray(), Is.EqualTo(box [| ("ufw", [ "--force"; "enable" ], None); ("ufw", [ "reload" ], None) |]))

    [<Test>]
    member _.``Journal schema accepts pending Delete state and rejects another owner``() =
        // Arrange
        let journal =
            JsonNode.Parse(
                """{"schemaVersion":1,"ownerId":"resource-a","baseline":{"enabled":false,"defaultIn":"deny","defaultOut":"allow","runtimeEnabled":false},"managed":{"enabled":false,"defaultIn":"deny","defaultOut":"allow","runtimeEnabled":false},"pending":null,"pendingRules":{"operation":"delete","beforeFiles":{"4":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","6":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"afterFiles":{"4":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","6":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"runtimeBefore":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","runtimeAfter":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","runtimeStopped":"0000000000000000000000000000000000000000000000000000000000000000"},"baselineRuntimeDigest":"1111111111111111111111111111111111111111111111111111111111111111","baselineStoppedRuntimeDigest":"2222222222222222222222222222222222222222222222222222222222222222"}"""
            ).AsObject()

        // Act
        let accepted = Ufw.validateJournal journal "resource-a"
        let wrongOwner = TestDelegate(fun () -> Ufw.validateJournal journal "another-resource" |> ignore)

        // Assert
        Assert.That(accepted, Is.SameAs(journal))
        Assert.Throws<Ufw.BackendError>(wrongOwner) |> ignore

    [<Test>]
    member _.``Delete recovery accepts either recorded file state and rejects outside drift``() =
        // Arrange
        let beforeFiles = Map.ofList [ "4", "old-v4"; "6", "old-v6" ]
        let afterFiles = Map.ofList [ "4", "new-v4"; "6", "old-v6" ]
        let before = JsonObject()
        before["4"] <- JsonValue.Create(digest (Map.find "4" beforeFiles))
        before["6"] <- JsonValue.Create(digest (Map.find "6" beforeFiles))
        let after = JsonObject()
        after["4"] <- JsonValue.Create(digest (Map.find "4" afterFiles))
        after["6"] <- JsonValue.Create(digest (Map.find "6" afterFiles))
        let pending = JsonObject()
        pending["beforeFiles"] <- before
        pending["afterFiles"] <- after
        pending["runtimeBefore"] <- JsonValue.Create "runtime-before"
        pending["runtimeAfter"] <- JsonValue.Create "runtime-after"
        pending["runtimeStopped"] <- JsonValue.Create "runtime-stopped"

        // Act
        let oldFiles = Ufw.validatePendingDelete pending beforeFiles afterFiles "runtime-before" "runtime-after" "runtime-stopped"
        let newFiles = Ufw.validatePendingDelete pending afterFiles afterFiles "runtime-before" "runtime-after" "runtime-stopped"
        let runtimeDrift = TestDelegate(fun () -> Ufw.validatePendingDelete pending afterFiles afterFiles "outside-runtime" "runtime-after" "runtime-stopped" |> ignore)

        // Assert
        Assert.That(oldFiles, Is.SameAs(pending))
        Assert.That(newFiles, Is.SameAs(pending))
        Assert.Throws<Ufw.BackendError>(runtimeDrift) |> ignore

    [<Test>]
    member _.``Runtime iptables comparison canonicalizes order masks inversions comments rates and reject defaults``() =
        // Arrange
        let persisted = "-A ufw-user-input -p tcp --dport 44444 -s 192.0.2.1 -j REJECT --reject-with tcp-reset"
        let runtime = "-A ufw-user-input -s 192.0.2.1/32 -p tcp -m tcp --dport 44444 -j REJECT --reject-with tcp-reset"
        let persistedV6 = "-A ufw6-user-input -d 2001:db8::1 -p udp --dport 53 -j ACCEPT"
        let runtimeV6 = "-A ufw6-user-input -p udp -m udp --dport 53 -d 2001:db8::1/128 -j ACCEPT"
        let invertedPersisted = "-A ufw-user-input ! -s 192.0.2.1 -p tcp --dport 44444 -j DROP"
        let invertedRuntime = "-A ufw-user-input -s ! 192.0.2.1/32 -p tcp -m tcp --dport 44444 -j DROP"
        let rejectPersisted = "-A ufw-user-input -p udp --dport 53 -j REJECT"
        let rejectRuntime = "-A ufw-user-input -p udp -m udp --dport 53 -j REJECT --reject-with icmp-port-unreachable"
        let commentPersisted = "-A ufw-user-input -m comment --comment 'dapp_Smoke%20Web' -p tcp --dport 80 -j ACCEPT"
        let commentRuntime = "-A ufw-user-input -p tcp -m tcp --dport 80 -m comment --comment \"dapp_Smoke%20Web\" -j ACCEPT"
        let recentPersisted = "-A ufw-user-input -p tcp -m conntrack --ctstate NEW -m recent --set -j ufw-user-limit"
        let recentRuntime = "-A ufw-user-input -p tcp -m tcp -m conntrack --ctstate NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource -j ufw-user-limit"
        let limitedPersisted = "-A ufw-user-limit -m limit --limit 3/minute -j REJECT"
        let limitedRuntime = "-A ufw-user-limit -m limit --limit 3/min -j REJECT"

        // Act
        let equalPairs =
            [ persisted, runtime
              persistedV6, runtimeV6
              invertedPersisted, invertedRuntime
              rejectPersisted, rejectRuntime
              commentPersisted, commentRuntime
              recentPersisted, recentRuntime
              limitedPersisted, limitedRuntime ]
            |> List.map (fun (left, right) -> Ufw.normalizeIptablesTokens left = Ufw.normalizeIptablesTokens right)
        let changedRecent = Ufw.normalizeIptablesTokens recentRuntime <> Ufw.normalizeIptablesTokens (recentRuntime.Replace("255.255.255.255", "255.255.0.0", StringComparison.Ordinal))

        // Assert
        Assert.That(equalPairs, Is.All.True)
        Assert.That(changedRecent, Is.True)


    [<Test>]
    member _.``Normalizer retains selectors and preserves opaque recent barriers``() =
        // Arrange
        let selectors = "-A ufw-user-input -p tcp --dport 18445 -s 192.0.2.1 -d 198.51.100.2 --sport 1234 -j ACCEPT"
        let recentAfterSelectors = "-A ufw-user-input -p tcp -m recent --set -m conntrack --ctstate NEW -s 192.0.2.1 -j ACCEPT"
        let selectorsAfterRecent = "-A ufw-user-input -s 192.0.2.1 -m recent --set -m conntrack --ctstate NEW -p tcp -j ACCEPT"

        // Act
        let normalizedSelectors = Ufw.normalizeIptablesTokens selectors
        let normalizedRecentAfter = Ufw.normalizeIptablesTokens recentAfterSelectors
        let normalizedSelectorsAfter = Ufw.normalizeIptablesTokens selectorsAfterRecent

        // Assert
        Assert.That(
            normalizedSelectors,
            Is.EqualTo(box [| "-A"; "ufw-user-input"; "-s"; "192.0.2.1/32"; "-d"; "198.51.100.2/32"; "-p"; "tcp"; "--sport"; "1234"; "--dport"; "18445"; "-j"; "ACCEPT" |])
        )
        Assert.That(
            normalizedRecentAfter,
            Is.EqualTo(box [| "-A"; "ufw-user-input"; "-p"; "tcp"; "-m"; "recent"; "--set"; "-m"; "conntrack"; "--ctstate"; "NEW"; "-s"; "192.0.2.1/32"; "-j"; "ACCEPT" |])
        )

    [<Test>]
    member _.``Runtime builtin policy drift is observable``() =
        // Arrange
        let table =
            runtimeTable
                "4"
                true
                false
                (Map.ofList [ "ufw-user-input", [||]; "ufw-user-output", [||]; "ufw-user-forward", [||] ])
                (Map.ofList
                    [ "ufw-skip-to-policy-input", [| [| "-A"; "ufw-skip-to-policy-input"; "-j"; "DROP" |] |]
                      "ufw-skip-to-policy-output", [| [| "-A"; "ufw-skip-to-policy-output"; "-j"; "ACCEPT" |] |]
                      "ufw-reject-input", [||]
                      "ufw-reject-output", [||] ])
                (Map.ofList [ "INPUT", "DROP"; "OUTPUT", "ACCEPT" ])
                Set.empty

        // Act
        let initialMatch = Ufw.runtimePoliciesMatch false true "deny" "allow" table None
        let details = Ufw.runtimePolicyDetails table "input"
        let drifted = { table with Policies = Map.add "INPUT" "ACCEPT" table.Policies }
        let driftedMatch = Ufw.runtimePoliciesMatch false true "deny" "allow" drifted None

        // Assert
        Assert.That(initialMatch, Is.True)
        Assert.That(details, Is.EqualTo((Some "deny", Some "DROP", Some "DROP", false)))
        Assert.That(driftedMatch, Is.False)
        let driftedPolicy, _, _, _ = Ufw.runtimePolicyDetails drifted "input"
        Assert.That(driftedPolicy, Is.EqualTo(Some "allow"))

    [<Test>]
    member _.``Runtime matching includes limit and user logging helper chains``() =
        // Arrange
        let input = "-A ufw-user-input -p tcp --dport 22 -j ACCEPT"
        let log = "-A ufw-user-logging-input -j ufw-logging-allow"
        let limit = "-A ufw-user-limit -m limit --limit 3/minute -j REJECT"
        let limitAccept = "-A ufw-user-limit-accept -j ACCEPT"
        let file =
            "*filter\n:ufw-user-input - [0:0]\n:ufw-user-output - [0:0]\n:ufw-user-forward - [0:0]\n"
            + ":ufw-user-limit - [0:0]\n:ufw-user-limit-accept - [0:0]\n:ufw-user-logging-input - [0:0]\n"
            + "### RULES ###\n" + input + "\n### END RULES ###\n### LOGGING ###\n" + log + "\n### END LOGGING ###\n"
            + "### RATE LIMITING ###\n" + limit + "\n" + limitAccept + "\n### END RATE LIMITING ###\nCOMMIT\n"
        let names = [ "ufw-user-input"; "ufw-user-output"; "ufw-user-forward"; "ufw-user-limit"; "ufw-user-limit-accept"; "ufw-user-logging-input" ]
        let allRules =
            Map.ofList
                [ "ufw-user-input", [| Ufw.normalizeIptablesTokens input |]
                  "ufw-user-output", [||]
                  "ufw-user-forward", [||]
                  "ufw-user-limit", [| Ufw.normalizeIptablesTokens limit |]
                  "ufw-user-limit-accept", [| Ufw.normalizeIptablesTokens limitAccept |]
                  "ufw-user-logging-input", [| Ufw.normalizeIptablesTokens log |] ]
        let table =
            runtimeTable
                "4"
                true
                false
                (Map.ofList [ "ufw-user-input", [| Ufw.normalizeIptablesTokens input |]; "ufw-user-output", [||]; "ufw-user-forward", [||] ])
                allRules
                (Map.ofList [ "INPUT", "DROP"; "OUTPUT", "ACCEPT" ])
                (Set.ofList names)
        let changedLimit = { table with AllRules = Map.add "ufw-user-limit" [||] table.AllRules }
        let changedPort = [| Ufw.normalizeIptablesTokens "-A ufw-user-input -p tcp --dport 23 -j ACCEPT" |]
        let wrongPortTable =
            { table with
                Rules = Map.add "ufw-user-input" changedPort table.Rules
                AllRules = Map.add "ufw-user-input" changedPort table.AllRules }

        // Act
        let matches = Ufw.runtimeRulesMatch false true table None file ""
        let wrongPort = Ufw.runtimeRulesMatch false true wrongPortTable None file ""
        let drift = Ufw.runtimeRulesMatch false true changedLimit None file ""

        // Assert
        Assert.That(matches, Is.True)
        Assert.That(wrongPort, Is.False)
        Assert.That(drift, Is.False)

    [<Test>]
    member _.``Detached stopped chains stay dormant but missing topology is partial``() =
        // Arrange
        let edges =
            Map.ofList
                [ "INPUT", set [ "ufw-before-logging-input"; "ufw-before-input"; "ufw-after-input"; "ufw-after-logging-input"; "ufw-reject-input"; "ufw-track-input" ]
                  "OUTPUT", set [ "ufw-before-logging-output"; "ufw-before-output"; "ufw-after-output"; "ufw-after-logging-output"; "ufw-reject-output"; "ufw-track-output" ]
                  "FORWARD", set [ "ufw-before-logging-forward"; "ufw-before-forward"; "ufw-after-forward"; "ufw-after-logging-forward"; "ufw-reject-forward"; "ufw-track-forward" ] ]
        let reachable = Ufw.runtimeUfwReachableChains "ufw" edges
        let chains = edges |> Map.toSeq |> Seq.collect snd |> Set.ofSeq
        let allRules = chains |> Seq.map (fun chain -> chain, [||]) |> Map.ofSeq
        let policies = Map.ofList [ "INPUT", "ACCEPT"; "OUTPUT", "ACCEPT"; "FORWARD", "ACCEPT" ]

        // Act
        let dormantPartial = Ufw.runtimeIsPartial "ufw" false reachable chains allRules policies
        let missingUser = Set.add "ufw-user-input" chains
        let partial = Ufw.runtimeIsPartial "ufw" false reachable missingUser allRules policies
        let emptyRules = Map.ofList [ "ufw-user-input", [||]; "ufw-user-output", [||]; "ufw-user-forward", [||] ]
        let dormant = runtimeTable "4" false false emptyRules allRules policies chains
        let withStaleUserRule = { dormant with Rules = Map.add "ufw-user-input" [| [| "-A"; "ufw-user-input"; "-j"; "ACCEPT" |] |] emptyRules }
        let emptyRules6 = Map.ofList [ "ufw6-user-input", [||]; "ufw6-user-output", [||]; "ufw6-user-forward", [||] ]
        let dormant6 = { dormant with Family = "6"; Rules = emptyRules6 }
        let digest = Ufw.runtimeDigest dormant (Some dormant6)
        let staleDigest = Ufw.runtimeDigest withStaleUserRule (Some dormant6)
        let activeRules =
            Map.ofList
                [ "ufw-user-input", [| [| "-A"; "ufw-user-input"; "-p"; "tcp"; "--dport"; "22"; "-j"; "ACCEPT" |] |]
                  "ufw-user-output", [||]
                  "ufw-user-forward", [||] ]
        let policyRules =
            Map.ofList
                [ "ufw-skip-to-policy-input", [| [| "-A"; "ufw-skip-to-policy-input"; "-j"; "DROP" |] |]
                  "ufw-skip-to-policy-output", [| [| "-A"; "ufw-skip-to-policy-output"; "-j"; "ACCEPT" |] |]
                  "ufw-reject-input", [||]
                  "ufw-reject-output", [||] ]
        let activeTable =
            runtimeTable
                "4"
                true
                false
                activeRules
                policyRules
                (Map.ofList [ "INPUT", "DROP"; "OUTPUT", "ACCEPT" ])
                Set.empty
        let activeDigest = Ufw.runtimeDigest activeTable None
        // Assert
        Assert.That(reachable.IsEmpty, Is.False)
        Assert.That(dormantPartial, Is.False)
        Assert.That(partial, Is.True)
        Assert.That(digest, Is.EqualTo(staleDigest))
        Assert.That(digest, Is.EqualTo("35dc7b35d6f48d8c7efc424080f066e11af5bff2b0e1638cb21fd848afe22d93"))
        Assert.That(activeDigest, Is.EqualTo("96b943200c177d1d26ed4c81e160c6a7b5ef1ff390bd84d8dd1c33b02fa99e14"))

    [<Test>]
    member _.``Runtime activation requires all builtin and before-to-user dispatch hooks``() =
        // Arrange
        let prefix = "ufw"
        let chains = set [ "ufw-before-input"; "ufw-before-output"; "ufw-before-forward"; "ufw-user-input"; "ufw-user-output"; "ufw-user-forward" ]
        let hooks = set [ "INPUT", "ufw-before-input"; "OUTPUT", "ufw-before-output"; "FORWARD", "ufw-before-forward" ]
        let dispatch = set [ "ufw-before-input", "ufw-user-input"; "ufw-before-output", "ufw-user-output" ]

        // Act
        let incomplete = Ufw.runtimeFamilyIsActive prefix chains hooks dispatch
        let complete = Set.add ("ufw-before-forward", "ufw-user-forward") dispatch |> Ufw.runtimeFamilyIsActive prefix chains hooks

        // Assert
        Assert.That(incomplete, Is.False)
        Assert.That(complete, Is.True)


    [<Test>]
    member _.``A stopped runtime selects a start action for an enabled target``() =
        // Arrange
        let runtimeEnabled = false
        let requestedEnabled = true

        // Act
        let action = Ufw.runtimeConvergenceAction runtimeEnabled requestedEnabled false false false false

        // Assert
        Assert.That(action, Is.EqualTo(UfwRuntimeAction.StartRuntime))


    [<Test>]
    member _.``Delete retry reloads when files are already updated but runtime is stale``() =
        // Arrange
        let runtimeEnabled = true
        let requestedEnabled = true
        let rulesChanged = false
        let runtimeNeedsRepair = true

        // Act
        let action = Ufw.runtimeConvergenceAction runtimeEnabled requestedEnabled false rulesChanged runtimeNeedsRepair false

        // Assert
        Assert.That(action, Is.EqualTo(UfwRuntimeAction.ReloadRuntime))

    [<Test>]
    member _.``Delete retry reconciles the kernel after both rule files were committed``() =
        // Arrange
        use temporary = new TemporaryDirectory("keroosha-ufw-delete-recovery-")
        let root = temporary.Path
        let mutable kernelHasOwner = true
        let mutable failFirstReload = true
        let owner = "delete-recovery-owner"
        let ownerMarker = Ufw.makeOwnerMarker owner 0 "both" "allow 22/tcp"
        let unmanagedMarker = "operator:unmanaged"
        let result exitCode stdout stderr =
            { ExitCode = exitCode
              Stdout = stdout
              Stderr = stderr }
        let prefixFor family = if family = "4" then "ufw" else "ufw6"
        let saveTable family includeOwner =
            let prefix = prefixFor family
            let declarations =
                [ "*filter"
                  ":INPUT DROP [0:0]"
                  ":OUTPUT ACCEPT [0:0]"
                  ":FORWARD DROP [0:0]"
                  ":" + prefix + "-before-input - [0:0]"
                  ":" + prefix + "-before-output - [0:0]"
                  ":" + prefix + "-before-forward - [0:0]"
                  ":" + prefix + "-user-input - [0:0]"
                  ":" + prefix + "-user-output - [0:0]"
                  ":" + prefix + "-user-forward - [0:0]"
                  ":" + prefix + "-skip-to-policy-input - [0:0]"
                  ":" + prefix + "-skip-to-policy-output - [0:0]"
                  ":" + prefix + "-reject-input - [0:0]"
                  ":" + prefix + "-reject-output - [0:0]" ]
            let hooks =
                [ "-A INPUT -j " + prefix + "-before-input"
                  "-A OUTPUT -j " + prefix + "-before-output"
                  "-A FORWARD -j " + prefix + "-before-forward"
                  "-A " + prefix + "-before-input -j " + prefix + "-user-input"
                  "-A " + prefix + "-before-output -j " + prefix + "-user-output"
                  "-A " + prefix + "-before-forward -j " + prefix + "-user-forward"
                  "-A " + prefix + "-skip-to-policy-input -j DROP"
                  "-A " + prefix + "-skip-to-policy-output -j ACCEPT" ]
            let userRules =
                [ "-A " + prefix + "-user-input -p tcp --dport 80 -j ACCEPT" ]
                @ (if includeOwner then [ "-A " + prefix + "-user-input -p tcp --dport 22 -j ACCEPT" ] else [])
            String.concat "\n" (declarations @ hooks @ userRules @ [ "COMMIT"; "" ])
        let nativeDryRun arguments =
            let commentIndex = arguments |> List.findIndex ((=) "comment")
            let markerValue = List.item (commentIndex + 1) arguments
            let ruleArguments = arguments |> List.skip 1 |> List.take (commentIndex - 1)
            let action = ruleArguments |> List.tryFind (fun item -> List.contains item [ "allow"; "deny"; "reject"; "limit" ]) |> Option.defaultValue "allow"
            let portToken = ruleArguments |> List.tryFind (fun item -> item.Contains('/', StringComparison.Ordinal)) |> Option.defaultValue "22/tcp"
            let slash = portToken.IndexOf('/')
            let port = if slash < 0 then portToken else portToken.Substring(0, slash)
            let protocol = if slash < 0 then "tcp" else portToken.Substring(slash + 1)
            let target = if action = "allow" then "ACCEPT" elif action = "reject" then "REJECT" else "DROP"
            let block family =
                let prefix = prefixFor family
                let address = if family = "4" then "0.0.0.0/0" else "::/0"
                let tuple = String.concat " " [ action; protocol; port; address; "any"; address; "in" ]
                "### tuple ### " + tuple + " comment=" + markerHex markerValue + "\n"
                + "-A " + prefix + "-user-input -p " + protocol + " --dport " + port + " -j " + target + "\n"
            "*filter\n### RULES ###\n" + block "4" + "\n" + block "6" + "\n### END RULES ###\nCOMMIT\n"
        let run (executable: string) (arguments: string list) (_input: string option) =
            match executable, arguments with
            | "ufw", [ "--version" ] -> result 0 "ufw 0.36.2\n" ""
            | ("ufw", "--dry-run" :: _) -> result 0 (nativeDryRun arguments) ""
            | "ufw", [ "reload" ] when failFirstReload ->
                failFirstReload <- false
                result 42 "" "injected reload interruption"
            | "ufw", [ "reload" ] ->
                kernelHasOwner <- false
                result 0 "Firewall reloaded\n" ""
            | "iptables-save", [ "-t"; "filter" ] -> result 0 (saveTable "4" kernelHasOwner) ""
            | "ip6tables-save", [ "-t"; "filter" ] -> result 0 (saveTable "6" kernelHasOwner) ""
            | "stat", _ ->
                let path = List.last arguments
                if Path.GetFileName(path) = "global.json" then result 0 "regular file:0:600\n" ""
                else result 0 "directory:0:700\n" ""
            | _ -> result 99 "" "unexpected test boundary call"
        let environment = TestSupport.fakeHostEnvironment root run (fun () -> DateTimeOffset.UnixEpoch)
        let mapped = HostEnvironment.path environment
        let createDirectory logicalPath = Directory.CreateDirectory(mapped logicalPath) |> ignore
        let writeFile (logicalPath: string) (contents: string) (mode: UnixFileMode) =
            let path = mapped logicalPath
            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
            File.WriteAllText(path, contents)
            File.SetUnixFileMode(path, mode)
            path
        for directory in
            [ "/run/lock"
              "/etc/default"
              "/etc/ufw"
              "/proc/sys/net/ipv6"
              "/var/lib/keroosha-iac/ufw" ] do
            createDirectory directory
        File.SetUnixFileMode(mapped "/var/lib/keroosha-iac/ufw", UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.UserExecute)
        let fileMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite
        let configMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite ||| UnixFileMode.GroupRead ||| UnixFileMode.OtherRead
        writeFile "/etc/default/ufw" "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\n" configMode |> ignore
        writeFile "/etc/ufw/ufw.conf" "ENABLED=yes\n" configMode |> ignore
        let userRuleFile family =
            let prefix = prefixFor family
            let unmanaged = makeBlock family unmanagedMarker "allow" "80" ("-A " + prefix + "-user-input -p tcp --dport 80 -j ACCEPT")
            let owned = makeBlock family ownerMarker "allow" "22" ("-A " + prefix + "-user-input -p tcp --dport 22 -j ACCEPT")
            let declarations =
                [ "*filter"
                  ":" + prefix + "-user-input - [0:0]"
                  ":" + prefix + "-user-output - [0:0]"
                  ":" + prefix + "-user-forward - [0:0]"
                  "### RULES ###" ]
            String.concat "\n" (declarations @ [ unmanaged.Lines[0]; unmanaged.Commands[0]; ""; owned.Lines[0]; owned.Commands[0]; ""; "### END RULES ###"; "COMMIT"; "" ])
        let user4 = userRuleFile "4"
        let user6 = userRuleFile "6"
        writeFile "/etc/ufw/user.rules" user4 fileMode |> ignore
        writeFile "/etc/ufw/user6.rules" user6 fileMode |> ignore
        let baseline4 = Ufw.parseRuntimeTable "4" (saveTable "4" false)
        let baseline6 = Ufw.parseRuntimeTable "6" (saveTable "6" false)
        let baseline =
            { Enabled = true
              DefaultIn = "deny"
              DefaultOut = "allow"
              RuntimeEnabled = true }
        let stoppedBaseline = { baseline with RuntimeEnabled = false }
        let emptyFiles = Map.ofList [ "4", ""; "6", "" ]
        let settingsNode =
            let node = JsonObject()
            node["enabled"] <- JsonValue.Create true
            node["defaultIn"] <- JsonValue.Create "deny"
            node["defaultOut"] <- JsonValue.Create "allow"
            node["runtimeEnabled"] <- JsonValue.Create true
            node
        let journal = JsonObject()
        journal["schemaVersion"] <- JsonValue.Create 1
        journal["ownerId"] <- JsonValue.Create owner
        journal["baseline"] <- settingsNode.DeepClone()
        journal["managed"] <- settingsNode.DeepClone()
        journal["pending"] <- null
        journal["pendingRules"] <- null
        journal["baselineRuntimeDigest"] <- JsonValue.Create(Ufw.runtimeDigest baseline4 (Some baseline6))
        journal["baselineStoppedRuntimeDigest"] <-
            JsonValue.Create(Ufw.expectedRuntimeDigest true emptyFiles stoppedBaseline baseline4 (Some baseline6))
        let journalPath = writeFile "/var/lib/keroosha-iac/ufw/global.json" (journal.ToJsonString() + "\n") fileMode
        use request = JsonDocument.Parse("{\"operation\":\"delete\",\"ownerId\":\"" + owner + "\"}")

        // Act
        let firstDelete = TestDelegate(fun () -> Ufw.handle environment request.RootElement |> ignore)

        // Assert
        Assert.Throws<Ufw.BackendError>(firstDelete) |> ignore
        Assert.That(kernelHasOwner, Is.True)
        Assert.That(File.ReadAllText(mapped "/etc/ufw/user.rules").Contains(markerHex ownerMarker), Is.False)
        Assert.That(File.ReadAllText(mapped "/etc/ufw/user6.rules").Contains(markerHex ownerMarker), Is.False)
        Assert.That((JsonNode.Parse(File.ReadAllText journalPath)).AsObject()["pendingRules"], Is.Not.Null)

        // Act
        let response = Ufw.handle environment request.RootElement

        // Assert
        Assert.That(kernelHasOwner, Is.False)
        Assert.That(response.AsObject().Count, Is.EqualTo(0))
        Assert.That(File.Exists journalPath, Is.False)
        Assert.That(File.ReadAllText(mapped "/etc/ufw/user.rules").Contains(markerHex ownerMarker), Is.False)
        Assert.That(File.ReadAllText(mapped "/etc/ufw/user.rules").Contains(markerHex unmanagedMarker), Is.True)
        Assert.That(File.ReadAllText(mapped "/etc/ufw/user6.rules").Contains(markerHex unmanagedMarker), Is.True)

    [<Test>]
    member _.``Dispatcher rejects unsupported operations before invoking host commands``() =
        // Arrange
        let mutable calls = 0
        let run _ _ _ =
            calls <- calls + 1
            { ExitCode = 0; Stdout = ""; Stderr = "" }
        let environment = TestSupport.fakeHostEnvironment "/" run (fun () -> DateTimeOffset.UnixEpoch)
        use document = JsonDocument.Parse("{\"operation\":\"reset\"}")

        // Act
        let action = TestDelegate(fun () -> Ufw.handle environment document.RootElement |> ignore)

        // Assert
        Assert.Throws<Ufw.BackendError>(action) |> ignore
        Assert.That(calls, Is.EqualTo(0))

    [<Test>]
    member _.``Fresh no-END apply and read preserve helper footer while rejecting raw main rules``() =
        // Arrange
        use temporary = new TemporaryDirectory("keroosha-ufw-no-end-lifecycle-")
        let root = temporary.Path
        let owner = "no-end-lifecycle-owner"
        let result exitCode stdout stderr =
            { ExitCode = exitCode
              Stdout = stdout
              Stderr = stderr }
        let emptyRuntime =
            "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"
        let nativeDryRun (arguments: string list) =
            let commentIndex = arguments |> List.findIndex ((=) "comment")
            let markerValue = List.item (commentIndex + 1) arguments
            let ruleArguments = arguments |> List.skip 1 |> List.take (commentIndex - 1)
            let action = ruleArguments |> List.tryFind (fun item -> List.contains item [ "allow"; "deny"; "reject"; "limit" ]) |> Option.defaultValue "allow"
            let portToken = ruleArguments |> List.tryFind (fun item -> item.Contains('/', StringComparison.Ordinal)) |> Option.defaultValue "22/tcp"
            let slash = portToken.IndexOf('/')
            let port = if slash < 0 then portToken else portToken.Substring(0, slash)
            let protocol = if slash < 0 then "tcp" else portToken.Substring(slash + 1)
            let target = if action = "allow" then "ACCEPT" elif action = "reject" then "REJECT" else "DROP"
            let block family =
                let prefix, address = if family = "4" then "ufw", "0.0.0.0/0" else "ufw6", "::/0"
                let tuple = String.concat " " [ action; protocol; port; address; "any"; address; "in" ]
                "### tuple ### " + tuple + " comment=" + markerHex markerValue + "\n"
                + "-A " + prefix + "-user-input -p " + protocol + " --dport " + port + " -j " + target + "\n"
            "*filter\n### RULES ###\n" + block "4" + "\n" + block "6" + "\n### END RULES ###\nCOMMIT\n"
        let run (executable: string) (arguments: string list) (_input: string option) =
            match executable, arguments with
            | "ufw", [ "--version" ] -> result 0 "ufw 0.36.2\n" ""
            | "ufw", "--dry-run" :: _ -> result 0 (nativeDryRun arguments) ""
            | "iptables-save", [ "-t"; "filter" ] -> result 0 emptyRuntime ""
            | "ip6tables-save", [ "-t"; "filter" ] -> result 0 emptyRuntime ""
            | "stat", _ ->
                if Path.GetFileName(List.last arguments) = "global.json" then result 0 "regular file:0:600\n" ""
                else result 0 "directory:0:700\n" ""
            | _ -> result 99 "" "unexpected test boundary call"
        let environment = TestSupport.fakeHostEnvironment root run (fun () -> DateTimeOffset.UnixEpoch)
        let mapped = HostEnvironment.path environment
        let createDirectory (logicalPath: string) = Directory.CreateDirectory(mapped logicalPath) |> ignore
        let writeFile (logicalPath: string) (contents: string) (mode: UnixFileMode) =
            let path = mapped logicalPath
            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
            File.WriteAllText(path, contents)
            File.SetUnixFileMode(path, mode)
            path
        for directory in
            [ "/run/lock"
              "/etc/default"
              "/etc/ufw"
              "/proc/sys/net/ipv6" ] do
            createDirectory directory
        let fileMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite
        let configMode = fileMode ||| UnixFileMode.GroupRead ||| UnixFileMode.OtherRead
        writeFile "/etc/default/ufw" "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n" configMode |> ignore
        writeFile "/etc/ufw/ufw.conf" "ENABLED=no\n" configMode |> ignore
        let noEndRules family includeRawMainRule =
            let prefix = if family = "4" then "ufw" else "ufw6"
            let helperLimit = "-A " + prefix + "-user-limit -m limit --limit 3/minute -j REJECT"
            let helperAccept = "-A " + prefix + "-user-limit-accept -j ACCEPT"
            let rawMainRule = "-A " + prefix + "-user-input -p udp --dport 53 -j ACCEPT"
            let mainRule = if includeRawMainRule then [ rawMainRule ] else []
            String.concat
                "\n"
                ([ "*filter"
                   ":" + prefix + "-user-input - [0:0]"
                   ":" + prefix + "-user-output - [0:0]"
                   ":" + prefix + "-user-forward - [0:0]"
                   ":" + prefix + "-user-limit - [0:0]"
                   ":" + prefix + "-user-limit-accept - [0:0]"
                   "### RULES ###" ]
                 @ mainRule
                 @ [ helperLimit; helperAccept; "COMMIT"; "" ])
        let user4 = noEndRules "4" true
        let user6 = noEndRules "6" false
        let cleanUser4 = noEndRules "4" false
        let user4Path = writeFile "/etc/ufw/user.rules" user4 fileMode
        let user6Path = writeFile "/etc/ufw/user6.rules" user6 fileMode
        let request operation =
            "{\"operation\":\"" + operation + "\",\"ownerId\":\"" + owner + "\",\"sshPort\":22,\"rules\":[[\"allow\",\"22/tcp\"]],\"enabled\":false,\"defaultIn\":\"deny\",\"defaultOut\":\"allow\"}"
        use applyRequest = JsonDocument.Parse(request "apply")
        use readRequest = JsonDocument.Parse(request "read")
        use deleteRequest = JsonDocument.Parse(request "delete")

        // Act: raw main-chain entries are still rejected before changing either file.
        let rawRuleAction = TestDelegate(fun () -> Ufw.handle environment applyRequest.RootElement |> ignore)

        // Assert
        Assert.Throws<Ufw.BackendError>(rawRuleAction) |> ignore
        Assert.That(File.ReadAllText user4Path, Is.EqualTo(user4))

        // Act: a fresh no-END seed with only native helper-chain footer rules is managed.
        writeFile "/etc/ufw/user.rules" cleanUser4 fileMode |> ignore
        let createResponse = Ufw.handle environment applyRequest.RootElement
        let readResponse = Ufw.handle environment readRequest.RootElement

        // Assert
        let expectedRules = box [| "[IPv4] allow 22/tcp"; "[IPv6] allow 22/tcp" |]
        for response in [ createResponse; readResponse ] do
            let value = response.AsObject()
            Assert.That(value["inSync"].GetValue<bool>(), Is.True)
            let actualRules = value["actualRules"].AsArray() |> Seq.map (fun rule -> rule.GetValue<string>()) |> Seq.toArray
            Assert.That(actualRules, Is.EqualTo(expectedRules))
        for path, family in [ user4Path, "4"; user6Path, "6" ] do
            let contents = File.ReadAllText path
            let prefix = if family = "4" then "ufw" else "ufw6"
            Assert.That(contents.Contains("### END RULES ###"), Is.False)
            Assert.That(contents.Contains("-A " + prefix + "-user-limit -m limit --limit 3/minute -j REJECT"), Is.True)
            Assert.That(contents.Contains("-A " + prefix + "-user-limit-accept -j ACCEPT"), Is.True)

        // Act: Delete restores both original no-END seeds and removes the ownership journal.
        let deleteResponse = Ufw.handle environment deleteRequest.RootElement

        // Assert
        Assert.That(deleteResponse.AsObject().Count, Is.EqualTo(0))
        Assert.That(File.ReadAllBytes user4Path, Is.EqualTo(box (Encoding.UTF8.GetBytes cleanUser4)))
        Assert.That(File.ReadAllBytes user6Path, Is.EqualTo(box (Encoding.UTF8.GetBytes user6)))
        Assert.That(File.Exists(mapped "/var/lib/keroosha-iac/ufw/global.json"), Is.False)
        for path, family in [ user4Path, "4"; user6Path, "6" ] do
            let contents = File.ReadAllText path
            let prefix = if family = "4" then "ufw" else "ufw6"
            Assert.That(contents.Contains("-A " + prefix + "-user-limit -m limit --limit 3/minute -j REJECT"), Is.True)
            Assert.That(contents.Contains("-A " + prefix + "-user-limit-accept -j ACCEPT"), Is.True)

    [<Test>]
    member _.``Native dry-run family omissions fail before mutation while explicit IPv4 default CIDR succeeds``() =
        // Arrange
        use temporary = new TemporaryDirectory("keroosha-ufw-family-coverage-")
        let root = temporary.Path
        let owner = "native-family-coverage-owner"
        let result exitCode stdout stderr =
            { ExitCode = exitCode
              Stdout = stdout
              Stderr = stderr }
        let emptyRuntime =
            "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"
        let nativeDryRun (arguments: string list) =
            let commentIndex = arguments |> List.findIndex ((=) "comment")
            let markerValue = List.item (commentIndex + 1) arguments
            let ruleArguments = arguments |> List.skip 1 |> List.take (commentIndex - 1)
            let action = List.head ruleArguments
            let port =
                match ruleArguments |> List.tryFindIndex ((=) "port") with
                | Some index when index + 1 < ruleArguments.Length -> ruleArguments[index + 1]
                | _ -> "18446"
            let protocol =
                match ruleArguments |> List.tryFindIndex ((=) "proto") with
                | Some index when index + 1 < ruleArguments.Length -> ruleArguments[index + 1]
                | _ -> "tcp"
            let target = if action = "allow" then "ACCEPT" else "DROP"
            let tuple = String.concat " " [ action; protocol; port; "0.0.0.0/0"; "any"; "0.0.0.0/0"; "in" ]
            "*filter\n### RULES ###\n### tuple ### "
            + tuple
            + " comment="
            + markerHex markerValue
            + "\n-A ufw-user-input -p "
            + protocol
            + " --dport "
            + port
            + " -j "
            + target
            + "\n### END RULES ###\nCOMMIT\n"
            + (if action = "limit" then "Rules updated\nSkipping unsupported IPv6 'limit' rule\n" else "Rules updated\n")
        let run (executable: string) (arguments: string list) (_input: string option) =
            match executable, arguments with
            | "ufw", [ "--version" ] -> result 0 "ufw 0.36.2\n" ""
            | "ufw", "--dry-run" :: _ -> result 0 (nativeDryRun arguments) ""
            | "iptables-save", [ "-t"; "filter" ] -> result 0 emptyRuntime ""
            | "ip6tables-save", [ "-t"; "filter" ] -> result 0 emptyRuntime ""
            | "stat", _ ->
                if Path.GetFileName(List.last arguments) = "global.json" then result 0 "regular file:0:600\n" ""
                else result 0 "directory:0:700\n" ""
            | _ -> result 99 "" "unexpected test boundary call"
        let environment = TestSupport.fakeHostEnvironment root run (fun () -> DateTimeOffset.UnixEpoch)
        let mapped = HostEnvironment.path environment
        let createDirectory (logicalPath: string) = Directory.CreateDirectory(mapped logicalPath) |> ignore
        let writeFile (logicalPath: string) (contents: string) (mode: UnixFileMode) =
            let path = mapped logicalPath
            Directory.CreateDirectory(Path.GetDirectoryName path) |> ignore
            File.WriteAllText(path, contents)
            File.SetUnixFileMode(path, mode)
            path
        for directory in
            [ "/run/lock"
              "/etc/default"
              "/etc/ufw"
              "/proc/sys/net/ipv6" ] do
            createDirectory directory
        let fileMode = UnixFileMode.UserRead ||| UnixFileMode.UserWrite
        let configMode = fileMode ||| UnixFileMode.GroupRead ||| UnixFileMode.OtherRead
        let defaultConfig = "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n"
        let ufwConfig = "ENABLED=no\n"
        writeFile "/etc/default/ufw" defaultConfig configMode |> ignore
        writeFile "/etc/ufw/ufw.conf" ufwConfig configMode |> ignore
        let emptyUserFile (family: string) =
            let prefix = if family = "4" then "ufw" else "ufw6"
            String.concat
                "\n"
                [ "*filter"
                  ":" + prefix + "-user-input - [0:0]"
                  ":" + prefix + "-user-output - [0:0]"
                  ":" + prefix + "-user-forward - [0:0]"
                  "### RULES ###"
                  "### END RULES ###"
                  "COMMIT"
                  "" ]
        let user4Seed = emptyUserFile "4"
        let user6Seed = emptyUserFile "6"
        let user4Path = writeFile "/etc/ufw/user.rules" user4Seed fileMode
        let user6Path = writeFile "/etc/ufw/user6.rules" user6Seed fileMode
        let request rule =
            "{\"operation\":\"apply\",\"ownerId\":\""
            + owner
            + "\",\"sshPort\":22,\"rules\":[["
            + rule
            + "]],\"enabled\":false,\"defaultIn\":\"deny\",\"defaultOut\":\"allow\"}"
        use missingV6Request = JsonDocument.Parse(request "\"limit\",\"in\",\"proto\",\"tcp\",\"to\",\"any\",\"port\",\"18446\"")
        use explicitV4Request = JsonDocument.Parse(request "\"allow\",\"from\",\"0.0.0.0/0\",\"proto\",\"tcp\",\"to\",\"any\",\"port\",\"18446\"")
        let journalDirectory = mapped "/var/lib/keroosha-iac/ufw"
        let journalPath = Path.Combine(journalDirectory, "global.json")

        // Act: native dry-run emits only IPv4 for a rule whose raw arguments request both families.
        let missingV6Action = TestDelegate(fun () -> Ufw.handle environment missingV6Request.RootElement |> ignore)

        // Assert
        let familyError = Assert.Throws<Ufw.BackendError>(missingV6Action)
        Assert.That(familyError.Message, Does.Contain("address families"))
        Assert.That(File.ReadAllText user4Path, Is.EqualTo(user4Seed))
        Assert.That(File.ReadAllText user6Path, Is.EqualTo(user6Seed))
        Assert.That(File.ReadAllText(mapped "/etc/default/ufw"), Is.EqualTo(defaultConfig))
        Assert.That(File.ReadAllText(mapped "/etc/ufw/ufw.conf"), Is.EqualTo(ufwConfig))
        Assert.That(Directory.Exists journalDirectory, Is.False)
        Assert.That(File.Exists journalPath, Is.False)

        // Act: the same native IPv4-only output is valid for an explicitly IPv4-wide source.
        let response = Ufw.handle environment explicitV4Request.RootElement

        // Assert
        let value = response.AsObject()
        Assert.That(value["inSync"].GetValue<bool>(), Is.True)
        let actualRules = value["actualRules"].AsArray() |> Seq.map (fun rule -> rule.GetValue<string>()) |> Seq.toArray
        Assert.That(actualRules, Is.EqualTo(box [| "[IPv4] allow 18446/tcp" |]))
        let v4Marker = Ufw.makeOwnerMarker owner 0 "v4" "allow 18446/tcp"
        Assert.That(File.ReadAllText user4Path, Does.Contain(markerHex v4Marker))
        Assert.That(File.ReadAllText user6Path, Does.Not.Contain(markerHex v4Marker))
