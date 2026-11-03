namespace Dorothy.DSL

open System
open System.Globalization
open System.Text

/// The default action used for inbound and outbound traffic.
type UfwPolicy =
    | Allow
    | Deny
    | Reject

/// The packet direction selected by a typed UFW rule.
type UfwDirection =
    | Incoming
    | Outgoing
    | Routed

/// The protocol selected for a typed UFW rule.
type UfwProtocol =
    | Tcp
    | Udp
    | TcpAndUdp

/// A transport declaration shared by firewall rules and Docker port publications.
type ProtocolSpec = { Value: UfwProtocol }

/// One immutable firewall configuration for a Debian host.
type UfwSpec internal (rules: string list list, enabled: bool, defaultIn: UfwPolicy, defaultOut: UfwPolicy) =
    member _.Rules = rules
    member _.Enabled = enabled
    member _.DefaultIn = defaultIn
    member _.DefaultOut = defaultOut

type UfwRuleSpec = private { Arguments: string list list }

type UfwRulePart =
    | Direction of UfwDirection
    | FromAddress of string
    | FromPort of string
    | ToAddress of string
    | ToPort of string
    | Protocol of UfwProtocol
    | InInterface of string
    | OutInterface of string

type UfwDeclaration =
    | DefaultIn of UfwPolicy
    | DefaultOut of UfwPolicy
    | Enabled of bool
    | Rule of UfwRuleSpec

module private UfwTokenization =
    let private forbiddenCharacters = [| ';'; '|'; '&'; '<'; '>'; '$'; '`'; '('; ')'; '{'; '}'; '\\' |]

    let tokenizeRule (rule: string) =
        if String.IsNullOrWhiteSpace rule then
            invalidArg "rule" "A raw UFW rule cannot be empty."

        if rule |> Seq.exists Char.IsControl then
            invalidArg "rule" "A raw UFW rule cannot contain control characters."

        if rule |> Seq.exists (fun character -> Char.IsWhiteSpace character && character <> ' ') then
            invalidArg "rule" "A raw UFW rule must use spaces between tokens."

        if rule.IndexOfAny forbiddenCharacters >= 0 then
            invalidArg "rule" "A raw UFW rule cannot contain shell operators."

        let tokens = ResizeArray<string>()
        let current = StringBuilder()
        let mutable quote = '\000'
        let mutable tokenStarted = false

        let finishToken () =
            if tokenStarted then
                if current.Length = 0 then
                    invalidArg "rule" "A raw UFW rule cannot contain an empty token."

                tokens.Add(current.ToString())
                current.Clear() |> ignore
                tokenStarted <- false

        for character in rule do
            if quote <> '\000' then
                if character = quote then
                    quote <- '\000'
                else
                    current.Append(character) |> ignore
            else
                match character with
                | quoteCharacter when quoteCharacter = char 39 || quoteCharacter = char 34 ->
                    quote <- quoteCharacter
                    tokenStarted <- true
                | ' ' -> finishToken ()
                | _ ->
                    current.Append(character) |> ignore
                    tokenStarted <- true

        if quote <> '\000' then
            invalidArg "rule" "A raw UFW rule cannot contain an unterminated quote."

        finishToken ()
        let tokens = tokens |> Seq.toList

        if tokens |> List.exists (fun token -> String.Equals(token, "comment", StringComparison.OrdinalIgnoreCase)) then
            invalidArg "rule" "Raw UFW rules cannot contain a comment token."

        if tokens |> List.exists (fun token -> token.StartsWith("-", StringComparison.Ordinal)) then
            invalidArg "rule" "Raw UFW rules cannot contain command-line options."

        let commandIndex =
            match tokens with
            | "route" :: _ -> 1
            | _ -> 0

        let command = tokens |> List.tryItem commandIndex

        match command with
        | Some ("allow" | "deny" | "reject" | "limit") ->
            match tokens with
            | commandToken :: tail when commandIndex = 0 -> commandToken.ToLowerInvariant() :: tail
            | "route" :: commandToken :: tail -> "route" :: commandToken.ToLowerInvariant() :: tail
            | _ -> invalidArg "rule" "A raw UFW rule must begin with allow, deny, reject, limit, or route followed by one of those rule actions."
        | _ -> invalidArg "rule" "A raw UFW rule must begin with allow, deny, reject, limit, or route followed by one of those rule actions."

module private UfwFormatting =
    let private validateRuleToken parameterName (value: string) =
        if String.IsNullOrWhiteSpace value
           || (value |> Seq.exists (fun character -> Char.IsWhiteSpace character || Char.IsControl character))
           || value.IndexOfAny([| ';'; '|'; '&'; '<'; '>'; '$'; '`'; '('; ')'; '{'; '}'; '\\'; '\''; '"' |]) >= 0
           || value.StartsWith("-", StringComparison.Ordinal) then
            invalidArg parameterName "A UFW rule token must be a non-empty, whitespace-free value and cannot be an option or shell expression."
        value

    let validateAddress (value: string) = validateRuleToken "address" value

    let validateInterface (value: string) = validateRuleToken "interface" value

    let portValue (value: int) =
        if value < 1 || value > 65535 then
            invalidArg "port" "A UFW port must be between 1 and 65535."
        value.ToString(CultureInfo.InvariantCulture)

    let protocolTokens = function
        | UfwProtocol.Tcp -> [ "tcp" ]
        | UfwProtocol.Udp -> [ "udp" ]
        | UfwProtocol.TcpAndUdp -> [ "tcp"; "udp" ]

/// Collects typed pieces of one UFW packet rule.
type UfwRuleBuilder internal (action: string) =
    member _.Yield(part: UfwRulePart) = [ part ]
    member _.Yield(protocol: ProtocolSpec) = [ Protocol protocol.Value ]
    member _.YieldFrom(parts: seq<UfwRulePart>) = Seq.toList parts
    member _.YieldFrom(protocols: seq<ProtocolSpec>) =
        protocols |> Seq.map (fun protocol -> Protocol protocol.Value) |> Seq.toList
    member _.Zero() = []
    member _.Combine(left: UfwRulePart list, right: UfwRulePart list) = left @ right
    member _.Delay(generator: unit -> UfwRulePart list) = generator()

    member _.For(values: seq<'T>, body: 'T -> UfwRulePart list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(parts: UfwRulePart list) =
        let mutable direction: UfwDirection option = None
        let mutable sourceAddress: string option = None
        let mutable sourcePort: string option = None
        let mutable destinationAddress: string option = None
        let mutable destinationPort: string option = None
        let mutable protocol: UfwProtocol option = None
        let mutable inInterface: string option = None
        let mutable outInterface: string option = None

        let duplicate fieldName =
            invalidArg "rule" ("A typed UFW rule may declare " + fieldName + " only once.")

        for part in parts do
            match part with
            | Direction value ->
                if Option.isSome direction then duplicate "direction"
                direction <- Some value
            | FromAddress value ->
                if Option.isSome sourceAddress then duplicate "fromAddress"
                sourceAddress <- Some value
            | FromPort value ->
                if Option.isSome sourcePort then duplicate "fromPort"
                sourcePort <- Some value
            | ToAddress value ->
                if Option.isSome destinationAddress then duplicate "toAddress"
                destinationAddress <- Some value
            | ToPort value ->
                if Option.isSome destinationPort then duplicate "toPort"
                destinationPort <- Some value
            | Protocol value ->
                if Option.isSome protocol then duplicate "proto"
                protocol <- Some value
            | InInterface value ->
                if Option.isSome inInterface then duplicate "inIface"
                inInterface <- Some value
            | OutInterface value ->
                if Option.isSome outInterface then duplicate "outIface"
                outInterface <- Some value

        let direction = defaultArg direction UfwDirection.Incoming

        match direction with
        | UfwDirection.Incoming when Option.isSome outInterface ->
            invalidArg "rule" "An incoming UFW rule cannot declare outIface."
        | UfwDirection.Outgoing when Option.isSome inInterface ->
            invalidArg "rule" "An outgoing UFW rule cannot declare inIface."
        | _ -> ()

        let prefix, interfaceArguments =
            match direction with
            | UfwDirection.Incoming ->
                [ action; "in" ],
                (inInterface
                 |> Option.map (fun name -> [ "on"; name ])
                 |> Option.defaultValue [])
            | UfwDirection.Outgoing ->
                [ action; "out" ],
                (outInterface
                 |> Option.map (fun name -> [ "on"; name ])
                 |> Option.defaultValue [])
            | UfwDirection.Routed ->
                let incoming =
                    inInterface
                    |> Option.map (fun name -> [ "in"; "on"; name ])
                    |> Option.defaultValue []

                let outgoing =
                    outInterface
                    |> Option.map (fun name -> [ "out"; "on"; name ])
                    |> Option.defaultValue []

                [ "route"; action ], incoming @ outgoing

        let sourceArguments =
            match sourceAddress, sourcePort with
            | None, None -> []
            | address, port ->
                [ "from"; defaultArg address "any" ]
                @ (port |> Option.map (fun value -> [ "port"; value ]) |> Option.defaultValue [])

        let destinationArguments =
            [ "to"; defaultArg destinationAddress "any" ]
            @ (destinationPort |> Option.map (fun value -> [ "port"; value ]) |> Option.defaultValue [])

        let protocolTokens =
            UfwFormatting.protocolTokens (defaultArg protocol UfwProtocol.Tcp)

        let arguments =
            protocolTokens
            |> List.map (fun protocolToken ->
                prefix
                @ interfaceArguments
                @ (protocol |> Option.map (fun _ -> [ "proto"; protocolToken ]) |> Option.defaultValue [])
                @ sourceArguments
                @ destinationArguments)

        Rule { Arguments = arguments }

/// Collects ordered UFW settings and rules into a host firewall configuration.
type UfwBuilder internal () =
    member _.Yield(declaration: UfwDeclaration) = [ declaration ]
    member _.YieldFrom(declarations: seq<UfwDeclaration>) = Seq.toList declarations
    member _.Zero() = []
    member _.Combine(left: UfwDeclaration list, right: UfwDeclaration list) = left @ right
    member _.Delay(generator: unit -> UfwDeclaration list) = generator()

    member _.For(values: seq<'T>, body: 'T -> UfwDeclaration list) =
        values |> Seq.collect body |> Seq.toList

    member _.Run(declarations: UfwDeclaration list) =
        let mutable enabled = true
        let mutable defaultIn = UfwPolicy.Deny
        let mutable defaultOut = UfwPolicy.Allow
        let mutable seenEnabled = false
        let mutable seenDefaultIn = false
        let mutable seenDefaultOut = false
        let mutable reversedRules = []

        for declaration in declarations do
            match declaration with
            | Enabled value ->
                if seenEnabled then
                    invalidArg "ufw" "Enabled may only be declared once."
                seenEnabled <- true
                enabled <- value
            | DefaultIn value ->
                if seenDefaultIn then
                    invalidArg "ufw" "DefaultIn may only be declared once."
                seenDefaultIn <- true
                defaultIn <- value
            | DefaultOut value ->
                if seenDefaultOut then
                    invalidArg "ufw" "DefaultOut may only be declared once."
                seenDefaultOut <- true
                defaultOut <- value
            | Rule rule ->
                reversedRules <- rule.Arguments |> List.fold (fun accumulated item -> item :: accumulated) reversedRules

        UfwSpec(List.rev reversedRules, enabled, defaultIn, defaultOut)

[<AutoOpen>]
module UfwBuilders =
    /// Builds an allow action for a typed UFW packet rule.
    let allow = UfwRuleBuilder("allow")

    /// Builds a deny action for a typed UFW packet rule.
    let deny = UfwRuleBuilder("deny")

    /// Builds a reject action for a typed UFW packet rule.
    let reject = UfwRuleBuilder("reject")

    /// Collects UFW defaults, enabled state, and ordered firewall rules.
    let ufw = UfwBuilder()

    /// Selects incoming, outgoing, or routed packet handling (incoming by default).
    let direction (value: UfwDirection) = Direction value

    /// Restricts a typed rule to packets from an address.
    let fromAddress (address: string) = FromAddress(UfwFormatting.validateAddress address)

    /// Restricts a typed rule to packets from a source port (1–65535).
    let fromPort (port: int) = FromPort(UfwFormatting.portValue port)

    /// Restricts a typed rule to packets sent to an address.
    let toAddress (address: string) = ToAddress(UfwFormatting.validateAddress address)

    /// Restricts a typed rule to a destination port (1–65535).
    let toPort (port: int) = ToPort(UfwFormatting.portValue port)

    /// Declares a transport for a firewall rule or Docker port publication.
    let proto (protocol: UfwProtocol) : ProtocolSpec = { Value = protocol }

    /// Restricts an incoming or routed rule to one incoming interface.
    let inIface (name: string) = InInterface(UfwFormatting.validateInterface name)

    /// Restricts an outgoing or routed rule to one outgoing interface.
    let outIface (name: string) = OutInterface(UfwFormatting.validateInterface name)

    /// Tokenizes a raw UFW rule after rejecting shell syntax and management commands.
    let raw (rule: string) =
        let arguments = UfwTokenization.tokenizeRule rule
        Rule { Arguments = [ arguments ] }
