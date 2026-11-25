namespace Dorothy.DSL

open System

[<RequireQualifiedAccess>]
type FirewalldTarget = Default | Accept | Drop | Reject | Continue

type FirewalldPart =
    internal
    | Target of FirewalldTarget
    | Interfaces of string list
    | Services of string list
    | Ports of string list
    | Protocols of string list
    | Masquerade of bool
    | Forward of bool
    | Ingress of string list
    | Egress of string list
    | Priority of int

/// A complete zone or policy, not an additive fragment.
type FirewalldObjectSpec internal (configuration: FirewalldModel.Configuration) =
    member _.Name = configuration.Name
    member _.Kind = configuration.Kind
    member _.Configuration = FirewalldModel.toJson configuration
    member internal _.Value = configuration

type FirewalldSpec internal (objects: FirewalldObjectSpec list, strictForwardPorts: bool option) =
    member _.Objects = objects
    member _.StrictForwardPorts = strictForwardPorts


[<Sealed>]
type FirewalldObjectBuilder internal (kind: string, name: string) =
    member _.Yield(part: FirewalldPart) = [ part ]
    member _.YieldFrom(parts: seq<FirewalldPart>) = Seq.toList parts
    member _.Zero() = []
    member _.Combine(left: FirewalldPart list, right: FirewalldPart list) = left @ right
    member _.Delay(body: unit -> FirewalldPart list) = body()
    member _.For(values: seq<'T>, body: 'T -> FirewalldPart list) = values |> Seq.collect body |> Seq.toList
    member _.Run(parts: FirewalldPart list) =
        let mutable configuration = FirewalldModel.empty kind name
        let seen = Collections.Generic.HashSet<string>(StringComparer.Ordinal)
        let once key =
            if not (seen.Add key) then invalidArg "firewalld" (key + " may only be declared once.")
        for part in parts do
            match part with
            | Target value ->
                once "target"
                configuration <-
                    { configuration with
                        Target =
                            match value with
                            | FirewalldTarget.Default -> "default"
                            | FirewalldTarget.Accept -> "ACCEPT"
                            | FirewalldTarget.Drop -> "DROP"
                            | FirewalldTarget.Reject -> if kind = "zone" then "%%REJECT%%" else "REJECT"
                            | FirewalldTarget.Continue -> "CONTINUE" }
            | Interfaces value -> once "interfaces"; configuration <- { configuration with Interfaces = value }
            | Services value -> once "services"; configuration <- { configuration with Services = value }
            | Ports value -> once "ports"; configuration <- { configuration with Ports = value }
            | Protocols value -> once "protocols"; configuration <- { configuration with Protocols = value }
            | Masquerade value -> once "masquerade"; configuration <- { configuration with Masquerade = value }
            | Forward value -> once "forward"; configuration <- { configuration with Forward = value }
            | Ingress value -> once "ingress"; configuration <- { configuration with Ingress = value }
            | Egress value -> once "egress"; configuration <- { configuration with Egress = value }
            | Priority value -> once "priority"; configuration <- { configuration with Priority = value }
        let allowed =
            if kind = "zone" then set [ "target"; "interfaces"; "services"; "ports"; "protocols"; "masquerade"; "forward" ]
            else set [ "target"; "ingress"; "egress"; "priority"; "masquerade" ]
        if seen |> Seq.exists (fun key -> not (allowed.Contains key)) then
            invalidArg "firewalld" ("Unsupported field for " + kind + ".")
        FirewalldObjectSpec(FirewalldModel.validate configuration)
[<RequireQualifiedAccess>]
type FirewalldDeclaration =
    | Object of FirewalldObjectSpec
    | StrictForwardPorts of bool

type FirewalldBuilder internal () =
    member _.Yield(value: FirewalldObjectSpec) = [ FirewalldDeclaration.Object value ]
    member _.Yield(value: FirewalldDeclaration) = [ value ]
    member _.YieldFrom(values: seq<FirewalldObjectSpec>) = values |> Seq.map FirewalldDeclaration.Object |> Seq.toList
    member _.YieldFrom(values: seq<FirewalldDeclaration>) = Seq.toList values
    member _.Zero() = []
    member _.Combine(left: FirewalldDeclaration list, right: FirewalldDeclaration list) = left @ right
    member _.Delay(body: unit -> FirewalldDeclaration list) = body()
    member _.For(values: seq<'T>, body: 'T -> FirewalldDeclaration list) = values |> Seq.collect body |> Seq.toList
    member _.Run(declarations: FirewalldDeclaration list) =
        let values = declarations |> List.choose (function FirewalldDeclaration.Object value -> Some value | _ -> None)
        let settings = declarations |> List.choose (function FirewalldDeclaration.StrictForwardPorts value -> Some value | _ -> None)
        if settings.Length > 1 then invalidArg "firewalld" "strictForwardPorts may be declared only once."
        let names = Collections.Generic.HashSet<string * string>()
        let interfaces = Collections.Generic.HashSet<string>(StringComparer.Ordinal)
        for value in values do
            if not (names.Add(value.Kind, value.Name)) then invalidArg "firewalld" "Duplicate zone or policy name."
            for iface in value.Value.Interfaces do
                if not (interfaces.Add iface) then invalidArg "firewalld" "An interface can belong to only one declared zone."
        FirewalldSpec(values, List.tryHead settings)
/// Open this module for the firewalld vocabulary; names do not shadow other host DSLs globally.
module Firewalld =
    let firewalld = FirewalldBuilder()
    let strictForwardPorts enabled = FirewalldDeclaration.StrictForwardPorts enabled
    let zone name = FirewalldObjectBuilder("zone", name)
    let policy name = FirewalldObjectBuilder("policy", name)
    let target value = Target value
    let interfaces values = Interfaces values
    let services values = Services values
    let ports (values: (int * UfwProtocol) list) =
        values
        |> List.collect (fun (number, protocol) ->
            let protocols = match protocol with Tcp -> [ "tcp" ] | Udp -> [ "udp" ] | TcpAndUdp -> [ "tcp"; "udp" ]
            protocols |> List.map (fun p -> sprintf "%d/%s" number p))
        |> Ports
    let portRanges values = Ports values
    let protocols values = Protocols values
    let masquerade value = Masquerade value
    let forward value = Forward value
    let ingressZones values = Ingress values
    let egressZones values = Egress values
    let priority value = Priority value
