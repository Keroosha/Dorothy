namespace Dorothy.Tests

open System
open Dorothy.DSL
open NUnit.Framework
open System.Collections.Immutable
open System.Threading.Tasks
open Pulumi
open Pulumi.Testing

[<Sealed>]
type private CapturingMocks() =
    let resources = ResizeArray<MockResourceArgs>()

    member _.Resources = resources.ToArray()

    interface IMocks with
        member _.NewResourceAsync(args: MockResourceArgs) =
            resources.Add(args)
            Task.FromResult((args.Name + "-id", box ImmutableDictionary<string, obj>.Empty))

        member _.CallAsync(_args: MockCallArgs) =
            Task.FromResult(box ImmutableDictionary<string, obj>.Empty)

        member _.RegisterResourceOutputs(_args: MockRegisterResourceOutputsRequest) =
            Task.CompletedTask

        member _.RegisterTransform(_transform: ResourceTransform) =
            Task.CompletedTask

        member _.RegisterInvokeTransform(_transform: InvokeTransform) =
            Task.CompletedTask

[<TestFixture>]
type AccessDslTests() =
    [<Test>]
    member _.``Users DSL builds typed accounts groups and authorized-key restrictions``() =
        let specification =
            users {
                group "package-operators" {
                    gid 2200
                    kind System
                    existing Adopt
                    state Present
                }
                user "operator" {
                    kind Human
                    description "Package maintenance operator"
                    primaryGroup PrivateGroup
                    supplementaryGroups (Managed [ "package-operators" ])
                    home (Home.Create("/home/operator", 0o700))
                    shell "/bin/bash"
                    password Password.Locked
                    onDelete RetainIdentity
                    authorizedKeys {
                        mode AuthorizedKeysMode.Exclusive
                        key "workstation" {
                            publicKey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample workstation"
                            restrict
                            allowPty true
                        }
                    }
                }
                user "application" {
                    kind System
                    home Home.None
                    shell "/usr/sbin/nologin"
                    password Password.Locked
                }
            }

        let group = specification.Groups["package-operators"]
        let operator = specification.Users["operator"]
        let workstation = operator.AuthorizedKeys.Value.Keys[0]
        let application = specification.Users["application"]

        Assert.That(group.Gid, Is.EqualTo(Some 2200))
        Assert.That(group.Kind, Is.EqualTo(Some UserKind.System))
        Assert.That(group.Existing, Is.EqualTo(Some Adopt))
        Assert.That(operator.Kind, Is.EqualTo(Some UserKind.Human))
        Assert.That(operator.Description, Is.EqualTo(Some "Package maintenance operator"))
        Assert.That(operator.PrimaryGroup, Is.EqualTo(Some PrivateGroup))
        Assert.That(operator.SupplementaryGroups, Is.EqualTo(Some(Managed [ "package-operators" ])))
        Assert.That(operator.Home, Is.EqualTo(Some(Home.Create("/home/operator", 0o700))))
        Assert.That(operator.Password, Is.EqualTo(Some Password.Locked))
        Assert.That(operator.OnDelete, Is.EqualTo(Some RetainIdentity))
        Assert.That(workstation.Id, Is.EqualTo("workstation"))
        Assert.That(workstation.Restrict, Is.EqualTo(Some true))
        Assert.That(workstation.AllowPty, Is.EqualTo(Some true))
        Assert.That(operator.AuthorizedKeys.Value.Mode, Is.EqualTo(AuthorizedKeysMode.Exclusive))
        Assert.That(application.Kind, Is.EqualTo(Some UserKind.System))
        Assert.That(application.Home, Is.EqualTo(Some Home.None))
        Assert.That(application.Shell, Is.EqualTo(Some "/usr/sbin/nologin"))

    [<Test>]
    member _.``Users DSL maps every optional account field with explicit ownership semantics``() =
        let hashInput = Input<string>.op_Implicit "test-secret-password-hash"
        let expiryDate = DateOnly(2030, 1, 2)
        let keyExpiry = DateTimeOffset(2030, 1, 2, 3, 4, 5, TimeSpan.Zero)
        let specification =
            users {
                user "operator" {
                    existing Adopt
                    state Present
                    kind Human
                    uid 2050
                    description "maintainer"
                    primaryGroup (ExistingGroup "staff")
                    supplementaryGroups (Exclusive [ "wheel" ])
                    home (Home.CreateWithSkeleton("/srv/operator", 0o750, "/etc/skel/operator"))
                    shell "/bin/zsh"
                    password (Password.Hash hashInput)
                    passwordUpdate PasswordUpdate.Always
                    accountExpiry (On expiryDate)
                    passwordPolicy {
                        minDays 2
                        maxDays 90
                        warnDays 7
                        inactiveDays 14
                    }
                    subordinateUids [ subordinateIdRange 100000 65536 ]
                    subordinateGids [ subordinateIdRange 165536 65536 ]
                    authorizedKeys {
                        mode AuthorizedKeysMode.Managed
                        key "automation" {
                            publicKey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIautomation automation"
                            comment "automation key"
                            allowAgentForwarding false
                            allowPortForwarding true
                            allowX11Forwarding false
                            allowUserRc false
                            allowFrom [ "192.0.2.0/24" ]
                            authorizedCommand "/usr/local/bin/automation"
                            keyExpires keyExpiry
                            permitOpen [ "db.internal:5432" ]
                            permitListen [ "127.0.0.1:9000" ]
                            verifyRequired true
                        }
                    }
                }
            }

        let operator = specification.Users["operator"]
        let key = operator.AuthorizedKeys.Value.Keys[0]
        Assert.That(operator.Existing, Is.EqualTo(Some Adopt))
        Assert.That(operator.State, Is.EqualTo(Some Present))
        Assert.That(operator.Uid, Is.EqualTo(Some 2050))
        Assert.That(operator.PrimaryGroup, Is.EqualTo(Some(ExistingGroup "staff")))
        Assert.That(operator.SupplementaryGroups, Is.EqualTo(Some(Exclusive [ "wheel" ])))
        Assert.That(operator.Home, Is.EqualTo(Some(Home.CreateWithSkeleton("/srv/operator", 0o750, "/etc/skel/operator"))))
        Assert.That(operator.PasswordUpdate, Is.EqualTo(Some PasswordUpdate.Always))
        Assert.That(operator.AccountExpiry, Is.EqualTo(Some(AccountExpiry.On expiryDate)))
        Assert.That(operator.PasswordPolicy.Value.MinDays, Is.EqualTo(Some 2))
        Assert.That(operator.PasswordPolicy.Value.MaxDays, Is.EqualTo(Some 90))
        Assert.That(operator.PasswordPolicy.Value.WarnDays, Is.EqualTo(Some 7))
        Assert.That(operator.PasswordPolicy.Value.InactiveDays, Is.EqualTo(Some 14))
        Assert.That(operator.SubordinateUids.Value, Is.EqualTo(box [ { Start = 100000; Count = 65536 } ]))
        Assert.That(operator.SubordinateGids.Value, Is.EqualTo(box [ { Start = 165536; Count = 65536 } ]))
        Assert.That(key.Comment, Is.EqualTo(Some "automation key"))
        Assert.That(key.AllowAgentForwarding, Is.EqualTo(Some false))
        Assert.That(key.AllowPortForwarding, Is.EqualTo(Some true))
        Assert.That(key.AllowX11Forwarding, Is.EqualTo(Some false))
        Assert.That(key.AllowUserRc, Is.EqualTo(Some false))
        Assert.That(key.AllowFrom, Is.EqualTo(box (Some [ "192.0.2.0/24" ])))
        Assert.That(key.Command, Is.EqualTo(Some "/usr/local/bin/automation"))
        Assert.That(key.Expires, Is.EqualTo(Some keyExpiry))
        Assert.That(key.PermitOpen, Is.EqualTo(box (Some [ "db.internal:5432" ])))
        Assert.That(key.PermitListen, Is.EqualTo(box (Some [ "127.0.0.1:9000" ])))
        Assert.That(key.VerifyRequired, Is.EqualTo(Some true))
        match operator.Password with
        | Some(Password.Hash _) -> Assert.Pass()
        | value -> Assert.Fail(sprintf "Expected a hashed password input, got %A." value)

    [<Test>]
    member _.``Unqualified password dispatch supports user and Traefik password inputs``() =
        let userPassword = password Password.Locked
        let certificatePassword = password (Output.CreateSecret "certificate-secret")
        let userPasswordIsLocked =
            match userPassword with
            | UserPart.UserPassword Password.Locked -> true
            | _ -> false
        let certificatePasswordIsTyped =
            match certificatePassword with
            | CertificatePart.Password _ -> true
            | _ -> false

        Assert.That(userPasswordIsLocked, Is.True)
        Assert.That(certificatePasswordIsTyped, Is.True)

    [<Test>]
    [<NonParallelizable>]
    member _.``Access resource registration preserves optional collections and UTC key expiry``() =
        let offsetExpiry = DateTimeOffset(2030, 1, 2, 3, 4, 5, TimeSpan.FromHours(2.0))
        let keyName = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIempty empty"
        let host =
            sshHost "access-wire" {
                Address "192.0.2.10"
                User "debian"
                debian {
                    users {
                        user "absent" {}
                        user "empty" {
                            subordinateUids []
                            subordinateGids []
                            authorizedKeys {
                                mode AuthorizedKeysMode.Exclusive
                                key "empty" {
                                    publicKey keyName
                                    allowFrom []
                                    permitOpen []
                                    permitListen []
                                }
                            }
                        }
                        user "expires" {
                            authorizedKeys {
                                mode AuthorizedKeysMode.Exclusive
                                key "expires" {
                                    publicKey keyName
                                    keyExpires offsetExpiry
                                }
                            }
                        }
                    }
                }
            }
        let mocks = CapturingMocks()
        Deployment.TestAsync(
            mocks,
            TestOptions(),
            Action(fun () -> Host.deploy host |> ignore)
        )
            .GetAwaiter()
            .GetResult()
        |> ignore

        let usersResource =
            mocks.Resources
            |> Array.find (fun resource -> resource.Type = "keroosha:debian:Users")
        let objectMap (value: obj) = unbox<ImmutableDictionary<string, obj>> value
        let property (values: ImmutableDictionary<string, obj>) name =
            match values.TryGetValue(name) with
            | true, value when not (isNull value) -> Some value
            | _ -> None
        let serializedUsers = objectMap usersResource.Inputs["users"]
        let absentUser = objectMap serializedUsers["absent"]
        let emptyUser = objectMap serializedUsers["empty"]
        let expiryUser = objectMap serializedUsers["expires"]

        Assert.That(Option.isNone (property absentUser "subordinateUids"), Is.True)
        Assert.That(Option.isNone (property absentUser "subordinateGids"), Is.True)
        let emptyUids = property emptyUser "subordinateUids"
        let emptyGids = property emptyUser "subordinateGids"
        Assert.That(Option.isSome emptyUids, Is.True)
        Assert.That(Option.isSome emptyGids, Is.True)
        let isEmptyList (value: obj option) =
            match value with
            | Some (:? System.Collections.IEnumerable as values) -> values |> Seq.cast<obj> |> Seq.isEmpty
            | _ -> false
        Assert.That(isEmptyList emptyUids, Is.True)
        Assert.That(isEmptyList emptyGids, Is.True)

        let emptyAuthorizedKeys = objectMap emptyUser["authorizedKeys"]
        let emptyKey =
            emptyAuthorizedKeys["keys"]
            |> fun values -> values :?> System.Collections.IEnumerable
            |> Seq.cast<obj>
            |> Seq.exactlyOne
            |> objectMap
        for field in [ "allowFrom"; "permitOpen"; "permitListen" ] do
            Assert.That(Option.isSome (property emptyKey field), Is.True, field)
            Assert.That(isEmptyList (property emptyKey field), Is.True, field)

        let expiryAuthorizedKeys = objectMap expiryUser["authorizedKeys"]
        let expiryKey =
            expiryAuthorizedKeys["keys"]
            |> fun values -> values :?> System.Collections.IEnumerable
            |> Seq.cast<obj>
            |> Seq.exactlyOne
            |> objectMap
        Assert.That(expiryKey["expires"], Is.EqualTo("2030-01-02T01:04:05.0000000Z"))

    [<Test>]
    member _.``Sudo DSL supports full passwordless grants and explicit command restrictions``() =
        let specification =
            sudo {
                grant "alice-admin" {
                    subjects [ SudoSubject.User "alice" ]
                    runAs AllUsersAndGroups
                    authentication Passwordless
                    allCommands
                }
                grant "package-maintenance" {
                    subjects [ SudoSubject.Group "package-operators" ]
                    runAsUser "root"
                    authentication Passwordless
                    (command "/usr/bin/apt") { arguments (Exact "update") }
                    (command "/usr/bin/apt") { arguments (Exact "upgrade") }
                    (command "/usr/bin/id") { arguments NoArguments }
                    (command "/usr/bin/env") { arguments AnyArguments }
                }
                grant "read-only" {
                    subjects [ SudoSubject.User "reader" ]
                    runAsUser "root"
                    runAsGroup "sudo"
                    (command "/usr/bin/id") { arguments NoArguments }
                }
            }

        let admin = specification.Grants["alice-admin"]
        let package = specification.Grants["package-maintenance"]
        Assert.That(admin.Subjects, Is.EqualTo(box [ SudoSubject.User "alice" ]))
        Assert.That(admin.RunAs, Is.EqualTo(AllUsersAndGroups))
        Assert.That(admin.Authentication, Is.EqualTo(Passwordless))
        Assert.That(admin.AllCommands, Is.True)
        Assert.That(admin.Commands, Is.Empty)
        Assert.That(package.Subjects, Is.EqualTo(box [ SudoSubject.Group "package-operators" ]))
        Assert.That(package.RunAs, Is.EqualTo(SpecificRunAs("root", None)))
        Assert.That(package.Authentication, Is.EqualTo(Passwordless))
        Assert.That(package.AllCommands, Is.False)
        Assert.That(package.Commands |> List.map (fun command -> command.Arguments), Is.EqualTo(box [ Exact "update"; Exact "upgrade"; NoArguments; AnyArguments ]))
        let readOnly = specification.Grants["read-only"]
        Assert.That(readOnly.RunAs, Is.EqualTo(SpecificRunAs("root", Some "sudo")))
        Assert.That(readOnly.Authentication, Is.EqualTo(Required))

    [<Test>]
    member _.``Access builders compose with conditionals yield-from loops and singleton Debian blocks``() =
        let includeTemporary = true
        let extraUsers = [ user "one" { kind Human }; user "two" { kind System } ]
        let userSpec =
            users {
                if includeTemporary then user "temporary" { state Absent }
                yield! extraUsers
            }
        let extraGrants = [ grant "read-only" { subjects [ SudoSubject.User "reader" ]; runAsUser "root"; (command "/usr/bin/id") { arguments NoArguments } } ]
        let sudoSpec =
            sudo {
                for grantSpec in extraGrants do grantSpec
            }
        let host =
            sshHost "access-host" {
                Address "192.0.2.25"
                User "debian"
                debian {
                    apt { "bash" }
                    userSpec
                    sudoSpec
                }
            }

        Assert.That(userSpec.Users.ContainsKey("temporary"), Is.True)
        Assert.That(userSpec.Users.ContainsKey("one"), Is.True)
        Assert.That(userSpec.Users.ContainsKey("two"), Is.True)
        Assert.That(sudoSpec.Grants.ContainsKey("read-only"), Is.True)
        Assert.That(host.Users.IsSome, Is.True)
        Assert.That(host.Sudo.IsSome, Is.True)
        Assert.That(host.Packages.ContainsKey("bash"), Is.True)
        Assert.Throws<ArgumentException>(TestDelegate(fun () ->
            debian { users {}; users {} } |> ignore)) |> ignore
        Assert.Throws<ArgumentException>(TestDelegate(fun () ->
            debian { sudo {}; sudo {} } |> ignore)) |> ignore

    [<Test>]
    member _.``Sudo command and run-as syntax coexists with Docker command and run-as syntax``() =
        let containerSpec =
            container "diagnostics" {
                image "debian:stable-slim"
                restart unlessStopped
                command [ "/usr/bin/id"; "-u" ]
                runAs "nobody"
            }
        let sudoSpec =
            sudo {
                grant "identity-check" {
                    subjects [ SudoSubject.User "debian" ]
                    runAs AllUsersAndGroups
                    (command "/usr/bin/id") { arguments (Exact "-u") }
                }
            }

        Assert.That(containerSpec.Command, Is.EqualTo(box (Some [ "/usr/bin/id"; "-u" ])))
        Assert.That(containerSpec.RunAs, Is.EqualTo(Some "nobody"))
        Assert.That(sudoSpec.Grants["identity-check"].Commands[0].Arguments, Is.EqualTo(SudoArguments.Exact "-u"))

    [<Test>]
    member _.``Access builders reject duplicate declarations and incomplete sudo policies``() =
        let duplicateUser = fun () -> users { user "alice" {}; user "alice" {} }
        let duplicateGroup = fun () -> users { group "operators" {}; group "operators" {} }
        let missingKeyMode = fun () -> user "alice" { authorizedKeys { key "key" { publicKey "ssh-ed25519 AAAA key" } } }
        let missingPassword = fun () -> user "alice" { passwordUpdate PasswordUpdate.Always }
        let missingSubjects = fun () -> sudo { grant "invalid" { runAsUser "root"; allCommands } }
        let missingRunAs = fun () -> sudo { grant "invalid" { subjects [ SudoSubject.User "alice" ]; allCommands } }
        let missingArguments = fun () -> sudo { grant "invalid" { subjects [ SudoSubject.User "alice" ]; runAsUser "root"; (command "/usr/bin/id") {} } }
        let emptyExact = fun () -> sudo { grant "invalid" { subjects [ SudoSubject.User "alice" ]; runAsUser "root"; (command "/usr/bin/id") { arguments (Exact "") } } }
        let mixedAllAndCommands = fun () -> sudo { grant "invalid" { subjects [ SudoSubject.User "alice" ]; runAsUser "root"; allCommands; (command "/usr/bin/id") { arguments NoArguments } } }

        let expectArgumentException action =
            Assert.Throws<ArgumentException>(TestDelegate(fun () -> action () |> ignore)) |> ignore
        expectArgumentException duplicateUser
        expectArgumentException duplicateGroup
        expectArgumentException missingKeyMode
        expectArgumentException missingPassword
        expectArgumentException missingSubjects
        expectArgumentException missingRunAs
        expectArgumentException missingArguments
        expectArgumentException emptyExact
        expectArgumentException mixedAllAndCommands
