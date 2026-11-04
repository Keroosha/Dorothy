namespace Dorothy.DSL

open System
open Pulumi

type UserKind =
    | Human
    | System

type ExistingIdentity =
    | Reject
    | Adopt

type UserState =
    | Present
    | Absent

type PrimaryGroup =
    | PrivateGroup
    | ExistingGroup of name: string

type SupplementaryGroups =
    | Managed of names: string list
    | Exclusive of names: string list

/// Home handling is explicit; CreateWithSkeleton supplies an optional skeleton source.
[<RequireQualifiedAccess>]
type Home =
    | Create of path: string * mode: int
    | CreateWithSkeleton of path: string * mode: int * skeleton: string
    | Existing of path: string
    | None

/// Hash inputs preserve Pulumi dependencies; Host.deploy always marks them as secrets.
[<RequireQualifiedAccess>]
type Password =
    | Locked
    | Hash of hash: Input<string>

[<RequireQualifiedAccess>]
type PasswordUpdate =
    | Always
    | OnCreate

type AccountExpiry =
    | Never
    | On of date: DateOnly

type UserDeleteBehavior =
    | RetainIdentity

[<RequireQualifiedAccess>]
type AuthorizedKeysMode =
    | Managed
    | Exclusive

type SubordinateIdRange =
    { Start: int
      Count: int }

type PasswordPolicySpec =
    { MinDays: int option
      MaxDays: int option
      WarnDays: int option
      InactiveDays: int option }

type AuthorizedKeySpec =
    { Id: string
      PublicKey: string
      Comment: string option
      Restrict: bool option
      AllowPty: bool option
      AllowAgentForwarding: bool option
      AllowPortForwarding: bool option
      AllowX11Forwarding: bool option
      AllowUserRc: bool option
      AllowFrom: string list option
      Command: string option
      Expires: DateTimeOffset option
      PermitOpen: string list option
      PermitListen: string list option
      VerifyRequired: bool option }

type AuthorizedKeysSpec =
    { Mode: AuthorizedKeysMode
      Keys: AuthorizedKeySpec list }

type UserGroupSpec =
    { Name: string
      Gid: int option
      Kind: UserKind option
      Existing: ExistingIdentity option
      State: UserState option }

type UserSpec =
    { Name: string
      State: UserState option
      Kind: UserKind option
      Existing: ExistingIdentity option
      Uid: int option
      Description: string option
      PrimaryGroup: PrimaryGroup option
      SupplementaryGroups: SupplementaryGroups option
      Home: Home option
      Shell: string option
      Password: Password option
      PasswordUpdate: PasswordUpdate option
      AccountExpiry: AccountExpiry option
      PasswordPolicy: PasswordPolicySpec option
      SubordinateUids: SubordinateIdRange list option
      SubordinateGids: SubordinateIdRange list option
      OnDelete: UserDeleteBehavior option
      AuthorizedKeys: AuthorizedKeysSpec option }

type UsersSpec internal (groups: Map<string, UserGroupSpec>, users: Map<string, UserSpec>) =
    member _.Groups = groups
    member _.Users = users

type UserPart =
    | GroupGid of int
    | Kind of UserKind
    | Existing of ExistingIdentity
    | State of UserState
    | UserUid of int
    | UserDescription of string
    | UserPrimaryGroup of PrimaryGroup
    | UserSupplementaryGroups of SupplementaryGroups
    | UserHome of Home
    | UserShell of string
    | UserPassword of Password
    | UserPasswordUpdate of PasswordUpdate
    | UserAccountExpiry of AccountExpiry
    | UserPasswordPolicy of PasswordPolicySpec
    | UserSubordinateUids of SubordinateIdRange list
    | UserSubordinateGids of SubordinateIdRange list
    | UserOnDelete of UserDeleteBehavior
    | UserAuthorizedKeys of AuthorizedKeysSpec

[<Sealed>]
type UserGroupBuilder internal (name: string) =
    member _.Yield(part: UserPart) = [ part ]
    member _.YieldFrom(parts: seq<UserPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: UserPart list, right: UserPart list) = left @ right
    member _.Delay(generator: unit -> UserPart list) = generator()
    member _.For(values: seq<'T>, body: 'T -> UserPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: UserPart list) =
        if String.IsNullOrWhiteSpace name then invalidArg "name" "A group name is required."
        let mutable gid = None
        let mutable kind = None
        let mutable existing = None
        let mutable state = None
        let assign field current value setter =
            if Option.isSome current then invalidArg "group" (sprintf "A group may declare %s only once." field)
            setter value
        for part in parts do
            match part with
            | GroupGid value -> assign "gid" gid value (fun item -> gid <- Some item)
            | Kind value -> assign "kind" kind value (fun item -> kind <- Some item)
            | Existing value -> assign "existing" existing value (fun item -> existing <- Some item)
            | State value -> assign "state" state value (fun item -> state <- Some item)
            | _ -> invalidArg "group" "A group declaration cannot contain user-only fields."
        { Name = name; Gid = gid; Kind = kind; Existing = existing; State = state }

type AuthorizedKeyPart =
    | KeyPublicKey of string
    | KeyComment of string
    | KeyRestrict of bool
    | KeyAllowPty of bool
    | KeyAllowAgentForwarding of bool
    | KeyAllowPortForwarding of bool
    | KeyAllowX11Forwarding of bool
    | KeyAllowUserRc of bool
    | KeyAllowFrom of string list
    | KeyCommand of string
    | KeyExpires of DateTimeOffset
    | KeyPermitOpen of string list
    | KeyPermitListen of string list
    | KeyVerifyRequired of bool

[<Sealed>]
type AuthorizedKeyBuilder internal (id: string) =
    member _.Yield(part: AuthorizedKeyPart) = [ part ]
    member _.YieldFrom(parts: seq<AuthorizedKeyPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: AuthorizedKeyPart list, right: AuthorizedKeyPart list) = left @ right
    member _.Delay(generator: unit -> AuthorizedKeyPart list) = generator()
    member _.For(values: seq<'T>, body: 'T -> AuthorizedKeyPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: AuthorizedKeyPart list) =
        if String.IsNullOrWhiteSpace id then invalidArg "id" "An authorized-key identity is required."
        let mutable publicKey = None
        let mutable comment = None
        let mutable restrict = None
        let mutable allowPty = None
        let mutable allowAgentForwarding = None
        let mutable allowPortForwarding = None
        let mutable allowX11Forwarding = None
        let mutable allowUserRc = None
        let mutable allowFrom = None
        let mutable command = None
        let mutable expires = None
        let mutable permitOpen = None
        let mutable permitListen = None
        let mutable verifyRequired = None
        let assign field current value setter =
            if Option.isSome current then invalidArg "key" (sprintf "An authorized key may declare %s only once." field)
            setter value
        for part in parts do
            match part with
            | KeyPublicKey value -> assign "publicKey" publicKey value (fun item -> publicKey <- Some item)
            | KeyComment value -> assign "comment" comment value (fun item -> comment <- Some item)
            | KeyRestrict value -> assign "restrict" restrict value (fun item -> restrict <- Some item)
            | KeyAllowPty value -> assign "allowPty" allowPty value (fun item -> allowPty <- Some item)
            | KeyAllowAgentForwarding value -> assign "allowAgentForwarding" allowAgentForwarding value (fun item -> allowAgentForwarding <- Some item)
            | KeyAllowPortForwarding value -> assign "allowPortForwarding" allowPortForwarding value (fun item -> allowPortForwarding <- Some item)
            | KeyAllowX11Forwarding value -> assign "allowX11Forwarding" allowX11Forwarding value (fun item -> allowX11Forwarding <- Some item)
            | KeyAllowUserRc value -> assign "allowUserRc" allowUserRc value (fun item -> allowUserRc <- Some item)
            | KeyAllowFrom value -> assign "allowFrom" allowFrom value (fun item -> allowFrom <- Some item)
            | KeyCommand value -> assign "command" command value (fun item -> command <- Some item)
            | KeyExpires value -> assign "expires" expires value (fun item -> expires <- Some item)
            | KeyPermitOpen value -> assign "permitOpen" permitOpen value (fun item -> permitOpen <- Some item)
            | KeyPermitListen value -> assign "permitListen" permitListen value (fun item -> permitListen <- Some item)
            | KeyVerifyRequired value -> assign "verifyRequired" verifyRequired value (fun item -> verifyRequired <- Some item)
        let publicKey =
            match publicKey with
            | Some value -> value
            | None -> invalidArg "key" "An authorized key requires a publicKey."
        { Id = id
          PublicKey = publicKey
          Comment = comment
          Restrict = restrict
          AllowPty = allowPty
          AllowAgentForwarding = allowAgentForwarding
          AllowPortForwarding = allowPortForwarding
          AllowX11Forwarding = allowX11Forwarding
          AllowUserRc = allowUserRc
          AllowFrom = allowFrom
          Command = command
          Expires = expires
          PermitOpen = permitOpen
          PermitListen = permitListen
          VerifyRequired = verifyRequired }

type AuthorizedKeysPart =
    | AuthorizedKeysMode of AuthorizedKeysMode
    | AuthorizedKey of AuthorizedKeySpec

[<Sealed>]
type AuthorizedKeysBuilder() =
    member _.Yield(part: AuthorizedKeysPart) = [ part ]
    member _.Yield(key: AuthorizedKeySpec) = [ AuthorizedKey key ]
    member _.YieldFrom(parts: seq<AuthorizedKeysPart>) = Seq.toList parts
    member _.YieldFrom(keys: seq<AuthorizedKeySpec>) = keys |> Seq.map AuthorizedKey |> Seq.toList
    member _.Zero() = []
    member _.Combine(left: AuthorizedKeysPart list, right: AuthorizedKeysPart list) = left @ right
    member _.Delay(generator: unit -> AuthorizedKeysPart list) = generator()
    member _.For(values: seq<'T>, body: 'T -> AuthorizedKeysPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: AuthorizedKeysPart list) =
        let mutable mode = None
        let mutable keys = Map.empty
        for part in parts do
            match part with
            | AuthorizedKeysMode value ->
                if Option.isSome mode then invalidArg "authorizedKeys" "The key collection mode may only be declared once."
                mode <- Some value
            | AuthorizedKey value ->
                if Map.containsKey value.Id keys then invalidArg "authorizedKeys" (sprintf "Authorized key '%s' is declared more than once." value.Id)
                keys <- Map.add value.Id value keys
        let mode =
            match mode with
            | Some value -> value
            | None -> invalidArg "authorizedKeys" "An authorized-keys collection mode is required."
        { Mode = mode; Keys = keys |> Map.toList |> List.map snd }

type PasswordPolicyPart =
    | PolicyMinDays of int
    | PolicyMaxDays of int
    | PolicyWarnDays of int
    | PolicyInactiveDays of int

[<Sealed>]
type PasswordPolicyBuilder() =
    member _.Yield(part: PasswordPolicyPart) = [ part ]
    member _.YieldFrom(parts: seq<PasswordPolicyPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: PasswordPolicyPart list, right: PasswordPolicyPart list) = left @ right
    member _.Delay(generator: unit -> PasswordPolicyPart list) = generator()
    member _.For(values: seq<'T>, body: 'T -> PasswordPolicyPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: PasswordPolicyPart list) =
        let mutable minDays = None
        let mutable maxDays = None
        let mutable warnDays = None
        let mutable inactiveDays = None
        let assign field current value setter =
            if Option.isSome current then invalidArg "passwordPolicy" (sprintf "%s may only be declared once." field)
            setter value
        for part in parts do
            match part with
            | PolicyMinDays value -> assign "minDays" minDays value (fun item -> minDays <- Some item)
            | PolicyMaxDays value -> assign "maxDays" maxDays value (fun item -> maxDays <- Some item)
            | PolicyWarnDays value -> assign "warnDays" warnDays value (fun item -> warnDays <- Some item)
            | PolicyInactiveDays value -> assign "inactiveDays" inactiveDays value (fun item -> inactiveDays <- Some item)
        if List.isEmpty parts then invalidArg "passwordPolicy" "At least one password policy field is required."
        { MinDays = minDays; MaxDays = maxDays; WarnDays = warnDays; InactiveDays = inactiveDays }


[<Sealed>]
type UserBuilder internal (name: string) =
    member _.Yield(part: UserPart) = [ part ]
    member _.Yield(specification: AuthorizedKeysSpec) = [ UserAuthorizedKeys specification ]
    member _.Yield(specification: PasswordPolicySpec) = [ UserPasswordPolicy specification ]
    member _.YieldFrom(parts: seq<UserPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: UserPart list, right: UserPart list) = left @ right
    member _.Delay(generator: unit -> UserPart list) = generator()
    member _.For(values: seq<'T>, body: 'T -> UserPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: UserPart list) =
        if String.IsNullOrWhiteSpace name then invalidArg "name" "A user name is required."
        let mutable state = None
        let mutable kind = None
        let mutable existing = None
        let mutable uid = None
        let mutable description = None
        let mutable primaryGroup = None
        let mutable supplementaryGroups = None
        let mutable home = None
        let mutable shell = None
        let mutable password = None
        let mutable passwordUpdate = None
        let mutable accountExpiry = None
        let mutable passwordPolicy = None
        let mutable subordinateUids = None
        let mutable subordinateGids = None
        let mutable onDelete = None
        let mutable authorizedKeys = None
        let assign field current value setter =
            if Option.isSome current then invalidArg "user" (sprintf "A user may declare %s only once." field)
            setter value
        for part in parts do
            match part with
            | GroupGid _ -> invalidArg "user" "gid can only be declared on a group."
            | State value -> assign "state" state value (fun item -> state <- Some item)
            | Kind value -> assign "kind" kind value (fun item -> kind <- Some item)
            | Existing value -> assign "existing" existing value (fun item -> existing <- Some item)
            | UserUid value -> assign "uid" uid value (fun item -> uid <- Some item)
            | UserDescription value -> assign "description" description value (fun item -> description <- Some item)
            | UserPrimaryGroup value -> assign "primaryGroup" primaryGroup value (fun item -> primaryGroup <- Some item)
            | UserSupplementaryGroups value -> assign "supplementaryGroups" supplementaryGroups value (fun item -> supplementaryGroups <- Some item)
            | UserHome value -> assign "home" home value (fun item -> home <- Some item)
            | UserShell value -> assign "shell" shell value (fun item -> shell <- Some item)
            | UserPassword value -> assign "password" password value (fun item -> password <- Some item)
            | UserPasswordUpdate value -> assign "passwordUpdate" passwordUpdate value (fun item -> passwordUpdate <- Some item)
            | UserAccountExpiry value -> assign "accountExpiry" accountExpiry value (fun item -> accountExpiry <- Some item)
            | UserPasswordPolicy value -> assign "passwordPolicy" passwordPolicy value (fun item -> passwordPolicy <- Some item)
            | UserSubordinateUids value -> assign "subordinateUids" subordinateUids value (fun item -> subordinateUids <- Some item)
            | UserSubordinateGids value -> assign "subordinateGids" subordinateGids value (fun item -> subordinateGids <- Some item)
            | UserOnDelete value -> assign "onDelete" onDelete value (fun item -> onDelete <- Some item)
            | UserAuthorizedKeys value -> assign "authorizedKeys" authorizedKeys value (fun item -> authorizedKeys <- Some item)
        if Option.isSome passwordUpdate && not (password |> Option.exists (function Password.Hash _ -> true | Password.Locked -> false)) then
            invalidArg "user" "passwordUpdate is valid only with a hashed password."
        { Name = name
          State = state
          Kind = kind
          Existing = existing
          Uid = uid
          Description = description
          PrimaryGroup = primaryGroup
          SupplementaryGroups = supplementaryGroups
          Home = home
          Shell = shell
          Password = password
          PasswordUpdate = passwordUpdate
          AccountExpiry = accountExpiry
          PasswordPolicy = passwordPolicy
          SubordinateUids = subordinateUids
          SubordinateGids = subordinateGids
          OnDelete = onDelete
          AuthorizedKeys = authorizedKeys }

type UsersDeclaration =
    | UserGroupDeclaration of UserGroupSpec
    | UserAccountDeclaration of UserSpec

[<Sealed>]
type UsersBuilder() =
    member _.Yield(declaration: UsersDeclaration) = [ declaration ]
    member _.Yield(specification: UserGroupSpec) = [ UserGroupDeclaration specification ]
    member _.Yield(specification: UserSpec) = [ UserAccountDeclaration specification ]
    member _.YieldFrom(groups: seq<UserGroupSpec>) = groups |> Seq.map UserGroupDeclaration |> Seq.toList
    member _.YieldFrom(users: seq<UserSpec>) = users |> Seq.map UserAccountDeclaration |> Seq.toList
    member _.YieldFrom(declarations: seq<UsersDeclaration>) = Seq.toList declarations
    member _.Zero() = []
    member _.Combine(left: UsersDeclaration list, right: UsersDeclaration list) = left @ right
    member _.Delay(generator: unit -> UsersDeclaration list) = generator()
    member _.For(values: seq<'T>, body: 'T -> UsersDeclaration list) = values |> Seq.collect body |> Seq.toList

    member _.Run(declarations: UsersDeclaration list) =
        let groups, users =
            declarations
            |> List.fold (fun (groups, users) declaration ->
                match declaration with
                | UserGroupDeclaration value ->
                    if Map.containsKey value.Name groups then invalidArg "users" (sprintf "Group '%s' is declared more than once." value.Name)
                    Map.add value.Name value groups, users
                | UserAccountDeclaration value ->
                    if Map.containsKey value.Name users then invalidArg "users" (sprintf "User '%s' is declared more than once." value.Name)
                    groups, Map.add value.Name value users) (Map.empty, Map.empty)
        UsersSpec(groups, users)


[<AutoOpen>]
module UserBuilders =
    let users = UsersBuilder()
    let group name = UserGroupBuilder(name)
    let user name = UserBuilder(name)
    let authorizedKeys = AuthorizedKeysBuilder()
    let passwordPolicy = PasswordPolicyBuilder()
    let key id = AuthorizedKeyBuilder(id)
    let gid value = GroupGid value
    let kind value = Kind value
    let existing value = Existing value
    let state value = State value
    let uid value = UserUid value
    let description value = UserDescription value
    let primaryGroup value = UserPrimaryGroup value
    let supplementaryGroups value = UserSupplementaryGroups value
    let home value = UserHome value
    let shell value = UserShell value
    let passwordUpdate value = UserPasswordUpdate value
    let accountExpiry value = UserAccountExpiry value
    let subordinateUids value = UserSubordinateUids value
    let subordinateGids value = UserSubordinateGids value
    let onDelete value = UserOnDelete value
    let mode value = AuthorizedKeysMode value
    let publicKey value = KeyPublicKey value
    let comment value = KeyComment value
    let restrict = KeyRestrict true
    let restrictKey value = KeyRestrict value
    let allowPty value = KeyAllowPty value
    let allowAgentForwarding value = KeyAllowAgentForwarding value
    let allowPortForwarding value = KeyAllowPortForwarding value
    let allowX11Forwarding value = KeyAllowX11Forwarding value
    let allowUserRc value = KeyAllowUserRc value
    let allowFrom value = KeyAllowFrom value
    let authorizedCommand value = KeyCommand value
    let keyExpires value = KeyExpires value
    let permitOpen value = KeyPermitOpen value
    let permitListen value = KeyPermitListen value
    let verifyRequired value = KeyVerifyRequired value
    let minDays value = PolicyMinDays value
    let maxDays value = PolicyMaxDays value
    let warnDays value = PolicyWarnDays value
    let inactiveDays value = PolicyInactiveDays value
    let subordinateIdRange start count = { Start = start; Count = count }
