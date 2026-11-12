namespace Dorothy.HostHelper

open System
open System.Globalization
open System.Text
open System.Text.Json
open System.Text.Json.Nodes

module Program =
    let private usage () =
        Console.Error.WriteLine("Usage: keroosha-iac-helper apt|ufw|firewalld|traefik|docker|swapfile|sshd|fail2ban|users|sudo|--version")
        64

    let private dispatch (command: string) (request: JsonElement) =
        match command with
        | "apt" -> Apt.handle HostEnvironment.system request
        | "ufw" -> Ufw.handle HostEnvironment.system request
        | "firewalld" -> Firewalld.handle HostEnvironment.system request
        | "traefik" -> Traefik.handle HostEnvironment.system request
        | "docker" -> DockerEngine.handle HostEnvironment.system request
        | "swapfile" -> Swapfile.handle HostEnvironment.system request
        | "sshd" -> Sshd.handle HostEnvironment.system request
        | "fail2ban" -> Fail2Ban.handle HostEnvironment.system request
        | "users" -> Users.handle HostEnvironment.system request
        | "sudo" -> Sudo.handle HostEnvironment.system request
        | _ -> invalidArg "command" "Unsupported helper command."

    let private verifyGlobalization () =
        try
            let normalized = "e\u0301".Normalize(NormalizationForm.FormC)
            let idn = IdnMapping()
            idn.UseStd3AsciiRules <- true
            let asciiHost = idn.GetAscii("b\u00FCcher.example")

            if normalized <> "\u00E9" || asciiHost <> "xn--bcher-kva.example" then
                raise (
                    HostPrerequisiteError(
                        "The native helper requires full Unicode normalization and IDN support; ensure a compatible ICU runtime is installed (Debian 13 package: libicu76)."
                    )
                )
        with
        | :? HostPrerequisiteError -> reraise ()
        | _ ->
            raise (
                HostPrerequisiteError(
                    "The native helper requires a compatible ICU runtime for full Unicode and IDN support; on Debian 13 install libicu76."
                )
            )

    let private reportFailure (error: exn) =
        let safeMessage =
            match error with
            | :? BackendError as backendError -> Some backendError.Message
            | :? Ufw.BackendError as backendError -> Some backendError.Message
            | :? Firewalld.BackendError as backendError -> Some backendError.Message
            | :? Traefik.BackendError as backendError -> Some backendError.Message
            | :? DockerEngine.BackendError as backendError -> Some backendError.Message
            | :? Swapfile.BackendError as backendError -> Some backendError.Message
            | :? Sshd.BackendError as backendError -> Some backendError.Message
            | :? Fail2Ban.BackendError as backendError -> Some backendError.Message
            | :? Users.BackendError as backendError -> Some backendError.Message
            | :? Sudo.BackendError as backendError -> Some backendError.Message
            | :? HostPrerequisiteError as prerequisiteError -> Some prerequisiteError.Message
            | _ -> None

        match safeMessage with
        | Some message when not (String.IsNullOrWhiteSpace message) ->
            let sanitized =
                message
                |> Seq.map (fun character -> if Char.IsControl character then ' ' else character)
                |> Array.ofSeq
                |> fun characters -> String(characters)

            Console.Error.WriteLine("keroosha-iac-helper: backend error: " + sanitized)
        | _ ->
            Console.Error.WriteLine("keroosha-iac-helper: request failed.")

    [<EntryPoint>]
    let main (arguments: string array) =
        if arguments.Length = 1 && arguments[0] = "--version" then
            try
                verifyGlobalization ()
                Console.Out.WriteLine("keroosha-iac-helper protocol 1")
                0
            with error ->
                reportFailure error
                1
        elif arguments.Length <> 1 then
            usage ()
        else
            match arguments[0] with
            | command when command = "apt" || command = "ufw" || command = "firewalld" || command = "traefik" || command = "docker" || command = "swapfile" || command = "sshd" || command = "fail2ban" || command = "users" || command = "sudo" ->
                try
                    verifyGlobalization ()
                    let requestText = Console.In.ReadToEnd()
                    use document = JsonDocument.Parse(requestText)
                    if document.RootElement.ValueKind <> JsonValueKind.Object then
                        invalidOp "The helper request must be a JSON object."
                    let response: JsonNode = dispatch command document.RootElement
                    Console.Out.WriteLine(response.ToJsonString())
                    0
                with error ->
                    reportFailure error
                    1
            | _ -> usage ()
