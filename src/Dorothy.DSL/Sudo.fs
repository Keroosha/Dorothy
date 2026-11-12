namespace Dorothy.DSL

open System
open Pulumi

[<RequireQualifiedAccess>]
type SudoSubject =
    | User of name: string
    | Group of name: string

type SudoAuthentication =
    | Required
    | Passwordless

type SudoRunAs =
    | AllUsersAndGroups
    | SpecificRunAs of user: string * group: string option

type SudoArguments =
    | NoArguments
    | Exact of argumentString: string
    /// Native sudoers wildcard match on the whole argument string: `*` matches any run of characters
    /// (spaces included), `?` one character. Other characters match literally; `[`/`]`/`\` are not accepted.
    | Glob of pattern: string
    | AnyArguments

type SudoCommandSpec =
    { Path: string
      Arguments: SudoArguments }

type SudoGrantSpec =
    { Name: string
      Subjects: SudoSubject list
      RunAs: SudoRunAs
      Authentication: SudoAuthentication
      AllCommands: bool
      Commands: SudoCommandSpec list }

[<Sealed>]
type SudoSpec internal (grants: Map<string, SudoGrantSpec>) =
    member _.Grants = grants

type SudoCommandPart =
    | CommandArguments of SudoArguments

[<Sealed>]
type SudoCommandBuilder internal (path: string) =
    member _.Yield(part: SudoCommandPart) = [ part ]
    member _.YieldFrom(parts: seq<SudoCommandPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: SudoCommandPart list, right: SudoCommandPart list) = left @ right
    member _.Delay(generator: unit -> SudoCommandPart list) = generator()
    member _.For(values: seq<'T>, body: 'T -> SudoCommandPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: SudoCommandPart list) =
        if String.IsNullOrWhiteSpace path then invalidArg "path" "A sudo command path is required."
        let arguments =
            match parts with
            | [ CommandArguments value ] -> value
            | [] -> invalidArg "command" "A sudo command requires an explicit arguments restriction."
            | _ -> invalidArg "command" "Sudo command arguments may only be declared once."
        match arguments with
        | Exact value when String.IsNullOrEmpty value -> invalidArg "arguments" "Use NoArguments rather than an empty Exact argument string."
        | Glob pattern when String.IsNullOrEmpty pattern -> invalidArg "arguments" "A Glob argument pattern cannot be empty."
        | Glob pattern when not (pattern.Contains('*') || pattern.Contains('?')) ->
            invalidArg "arguments" "A Glob argument pattern must contain * or ?; use Exact for a literal argument string."
        | Glob pattern when pattern.IndexOfAny([| '['; ']'; '\\' |]) >= 0 ->
            invalidArg "arguments" "Glob argument patterns support only * and ? wildcards; [ ] and \\ are not accepted."
        | _ -> ()
        { Path = path; Arguments = arguments }

type SudoGrantPart =
    | GrantSubjects of SudoSubject list
    | GrantRunAs of SudoRunAs
    | GrantRunAsUser of string
    | GrantRunAsGroup of string
    | GrantAuthentication of SudoAuthentication
    | GrantAllCommands
    | GrantCommand of SudoCommandSpec

[<Sealed>]
type SudoGrantBuilder internal (name: string) =
    member _.Yield(part: SudoGrantPart) = [ part ]
    member _.Yield(command: SudoCommandSpec) = [ GrantCommand command ]
    member _.YieldFrom(parts: seq<SudoGrantPart>) = Seq.toList parts
    member _.YieldFrom(commands: seq<SudoCommandSpec>) = commands |> Seq.map GrantCommand |> Seq.toList
    member _.Zero() = []
    member _.Combine(left: SudoGrantPart list, right: SudoGrantPart list) = left @ right
    member _.Delay(generator: unit -> SudoGrantPart list) = generator()
    member _.For(values: seq<'T>, body: 'T -> SudoGrantPart list) = values |> Seq.collect body |> Seq.toList

    member _.Run(parts: SudoGrantPart list) =
        if String.IsNullOrWhiteSpace name then invalidArg "name" "A sudo grant name is required."
        let mutable subjects = None
        let mutable runAs = None
        let mutable runAsUser = None
        let mutable runAsGroup = None
        let mutable authentication = None
        let mutable allCommands = false
        let mutable allCommandsDeclared = false
        let mutable commands = []
        let assign field current value setter =
            if Option.isSome current then invalidArg "grant" (sprintf "%s may only be declared once." field)
            setter value
        for part in parts do
            match part with
            | GrantSubjects value -> assign "subjects" subjects value (fun item -> subjects <- Some item)
            | GrantRunAs value -> assign "runAs" runAs value (fun item -> runAs <- Some item)
            | GrantRunAsUser value -> assign "runAsUser" runAsUser value (fun item -> runAsUser <- Some item)
            | GrantRunAsGroup value -> assign "runAsGroup" runAsGroup value (fun item -> runAsGroup <- Some item)
            | GrantAuthentication value -> assign "authentication" authentication value (fun item -> authentication <- Some item)
            | GrantAllCommands ->
                if allCommandsDeclared then invalidArg "grant" "allCommands may only be declared once."
                allCommandsDeclared <- true
                allCommands <- true
            | GrantCommand value -> commands <- value :: commands
        let subjects =
            match subjects with
            | Some values when not (List.isEmpty values) ->
                let unique = values |> Set.ofList
                if unique.Count <> values.Length then invalidArg "grant" "A sudo grant cannot repeat a subject."
                values
            | _ -> invalidArg "grant" "A sudo grant requires at least one subject."
        let runAs =
            match runAs with
            | Some value when Option.isSome runAsUser || Option.isSome runAsGroup ->
                invalidArg "grant" "Use either runAs or runAsUser/runAsGroup, not both."
            | Some value -> value
            | None ->
                match runAsUser, runAsGroup with
                | Some user, group -> SudoRunAs.SpecificRunAs(user, group)
                | None, Some _ -> invalidArg "grant" "runAsGroup requires runAsUser."
                | None, None -> invalidArg "grant" "A sudo grant requires runAs AllUsersAndGroups or runAsUser."
        let commands = List.rev commands
        if allCommands && not (List.isEmpty commands) then
            invalidArg "grant" "allCommands cannot be combined with command declarations."
        if not allCommands && List.isEmpty commands then
            invalidArg "grant" "A grant must declare allCommands or at least one command."
        let duplicates =
            commands
            |> List.groupBy (fun command -> command.Path, command.Arguments)
            |> List.exists (fun (_, values) -> values.Length > 1)
        if duplicates then invalidArg "grant" "A sudo grant cannot repeat a command with the same argument restriction."
        { Name = name
          Subjects = subjects
          RunAs = runAs
          Authentication = defaultArg authentication SudoAuthentication.Required
          AllCommands = allCommands
          Commands = commands }

type SudoDeclaration =
    | GrantDeclaration of SudoGrantSpec

[<Sealed>]
type SudoBuilder() =
    member _.Yield(declaration: SudoDeclaration) = [ declaration ]
    member _.Yield(grant: SudoGrantSpec) = [ GrantDeclaration grant ]
    member _.YieldFrom(declarations: seq<SudoDeclaration>) = Seq.toList declarations
    member _.YieldFrom(grants: seq<SudoGrantSpec>) = grants |> Seq.map GrantDeclaration |> Seq.toList
    member _.Zero() = []
    member _.Combine(left: SudoDeclaration list, right: SudoDeclaration list) = left @ right
    member _.Delay(generator: unit -> SudoDeclaration list) = generator()
    member _.For(values: seq<'T>, body: 'T -> SudoDeclaration list) = values |> Seq.collect body |> Seq.toList

    member _.Run(declarations: SudoDeclaration list) =
        let grants =
            declarations
            |> List.fold (fun grants declaration ->
                let value = match declaration with GrantDeclaration grant -> grant
                if Map.containsKey value.Name grants then invalidArg "sudo" (sprintf "Sudo grant '%s' is declared more than once." value.Name)
                Map.add value.Name value grants) Map.empty
        SudoSpec grants

/// Typed static dispatch preserves Docker's unqualified command/runAs DSL alongside sudo.
[<AbstractClass; Sealed>]
type CommandFields private () =
    static member Command(path: string) = SudoCommandBuilder(path)
    static member Command(arguments: string list) = DockerContainerPart.Command arguments

[<AbstractClass; Sealed>]
type RunAsFields private () =
    static member RunAs(value: SudoRunAs) = GrantRunAs value
    static member RunAs(user: string) = DockerContainerPart.RunAs user

[<AbstractClass; Sealed>]
type PasswordFields private () =
    static member Password(value: Password) = UserPassword value
    static member Password(value: string) = TraefikFields.Password value
    static member Password(value: Output<string>) = TraefikFields.Password value


[<AutoOpen>]
module SudoBuilders =
    let sudo = SudoBuilder()
    let inline password (value: ^T) : ^U =
        ((^T or PasswordFields) : (static member Password: ^T -> ^U) value)
    let grant name = SudoGrantBuilder(name)
    let inline command (value: ^T) : ^U =
        ((^T or CommandFields) : (static member Command: ^T -> ^U) value)
    let subjects values = GrantSubjects values
    let inline runAs (value: ^T) : ^U =
        ((^T or RunAsFields) : (static member RunAs: ^T -> ^U) value)
    let runAsUser value = GrantRunAsUser value
    let runAsGroup value = GrantRunAsGroup value
    let authentication value = GrantAuthentication value
    let allCommands = GrantAllCommands
    let arguments value = CommandArguments value
