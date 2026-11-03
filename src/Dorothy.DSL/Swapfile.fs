namespace Dorothy.DSL

open System

/// One immutable, explicitly sized swap file for a Debian host.
[<Sealed>]
type SwapfileSpec internal (path: string, size: int<MiB>) =
    member _.Path = path
    member _.Size = size

type SwapfilePart =
    | SwapfilePath of string
    | SwapfileSize of int<MiB>

module internal SwapfileValidation =
    let validatePath (path: string) =
        let validCharacter (character: char) =
            (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
            || character = '_'
            || character = '-'
            || character = '.'
            || character = '+'

        let validSegment (segment: string) =
            segment.Length > 0
            && segment <> "."
            && segment <> ".."
            && (segment |> Seq.forall validCharacter)

        if String.IsNullOrWhiteSpace path
           || path[0] <> '/'
           || path = "/"
           || path.EndsWith("/", StringComparison.Ordinal)
           || not (path.Substring(1).Split('/') |> Array.forall validSegment) then
            invalidArg "path" "A swapfile path must be a canonical absolute path with safe path components."

    let validateSize (size: int<MiB>) =
        if size <= 0<MiB> then
            invalidArg "size" "A swapfile size must be a positive number of MiB."

    let create path size =
        validatePath path
        validateSize size
        SwapfileSpec(path, size)

/// Builds the required path and size declaration for one managed swap file.
type SwapfileBuilder() =
    member _.Yield(part: SwapfilePart) = [ part ]
    member _.Zero() = []
    member _.Combine(left: SwapfilePart list, right: SwapfilePart list) = left @ right
    member _.Delay(generator: unit -> SwapfilePart list) = generator()

    member _.Run(parts: SwapfilePart list) =
        let path, size =
            parts
            |> List.fold (fun (path, size) part ->
                match part with
                | SwapfilePath value ->
                    match path with
                    | Some _ -> invalidArg "swapfile" "A swapfile path may only be declared once."
                    | None -> Some value, size
                | SwapfileSize value ->
                    match size with
                    | Some _ -> invalidArg "swapfile" "A swapfile size may only be declared once."
                    | None -> path, Some value) (None, None)

        let path =
            match path with
            | Some value -> value
            | None -> invalidArg "swapfile" "A swapfile path is required."

        let size =
            match size with
            | Some value -> value
            | None -> invalidArg "swapfile" "A swapfile size is required."

        SwapfileValidation.create path size

[<AutoOpen>]
module SwapfileBuilders =
    let swapfile = SwapfileBuilder()
    let path value = SwapfilePath value
    let size (value: int<MiB>) = SwapfileSize value
