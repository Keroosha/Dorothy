namespace Dorothy.HostHelper

open System
open System.Globalization
open System.IO
open System.Runtime.InteropServices
open System.Text
open System.Text.Json
open System.Text.Json.Nodes

// Debian's firewalld nftables backend uses libnftables1. A minimal installation
// need not include the optional nft executable or enable nftables.service.
module private FirewalldNftTable =
    [<DllImport("libnftables.so.1")>]
    extern nativeint nft_ctx_new(uint32 flags)
    [<DllImport("libnftables.so.1")>]
    extern void nft_ctx_free(nativeint ctx)
    [<DllImport("libnftables.so.1")>]
    extern void nft_ctx_output_set_flags(nativeint ctx, uint32 flags)
    [<DllImport("libnftables.so.1")>]
    extern int nft_ctx_buffer_output(nativeint ctx)
    [<DllImport("libnftables.so.1")>]
    extern int nft_ctx_buffer_error(nativeint ctx)
    [<DllImport("libnftables.so.1")>]
    extern nativeint nft_ctx_get_output_buffer(nativeint ctx)
    [<DllImport("libnftables.so.1")>]
    extern int nft_run_cmd_from_buffer(nativeint ctx, [<MarshalAs(UnmanagedType.LPUTF8Str)>] string cmd)

    let printTable () =
        let ctx = nft_ctx_new 0u
        if ctx = 0n then 1
        else
            try
                nft_ctx_output_set_flags(ctx, 16u) // NFT_CTX_OUTPUT_JSON
                if nft_ctx_buffer_output(ctx) < 0 || nft_ctx_buffer_error(ctx) < 0
                   || nft_run_cmd_from_buffer(ctx, "list table inet firewalld") <> 0 then 1
                else
                    let output = nft_ctx_get_output_buffer ctx
                    if output = 0n then 1
                    else
                        Console.Out.Write(Marshal.PtrToStringUTF8 output)
                        0
            finally nft_ctx_free ctx

module Program =
    let private usage () =
        Console.Error.WriteLine("Usage: keroosha-iac-helper apt|ufw|firewalld|firewalld-recover|firewalld-recover-boot|firewalld-recover-postboot|firewalld-docker-gate NAME PRIORITY INGRESS EGRESS|traefik|docker|docker-job|sshd|fail2ban|users|sudo|content|service|swapfile|--version")
        64

    // A disconnected provider must not leave an external command holding the
    // transaction lock indefinitely. Independent recovery will retry once the
    // lock is released; unsuccessful commands never attest a successful reload.
    let private firewalldEnvironment =
        let host = HostEnvironment.system
        { host with
            Run = fun executable arguments input ->
                let executable, arguments =
                    match executable, arguments with
                    | "nft", [ "-j"; "list"; "table"; "inet"; "firewalld" ] ->
                        if File.Exists "/usr/sbin/nft" then "/usr/sbin/nft", arguments
                        else Environment.ProcessPath, [ "firewalld-nft-table" ]
                    | _ -> executable, arguments
                host.Run "/usr/bin/timeout" ("--kill-after=5s" :: "75s" :: executable :: arguments) input }

    let private dispatch (command: string) (request: JsonElement) =
        match command with
        | "apt" -> Apt.handle HostEnvironment.system request
        | "ufw" -> Ufw.handle HostEnvironment.system request
        | "firewalld" -> Firewalld.handle firewalldEnvironment request
        | "traefik" -> Traefik.handle HostEnvironment.system request
        | "docker" -> DockerEngine.handle HostEnvironment.system request
        | "docker-job" -> DockerJob.handle HostEnvironment.system request
        | "swapfile" -> Swapfile.handle HostEnvironment.system request
        | "sshd" -> Sshd.handle HostEnvironment.system request
        | "fail2ban" -> Fail2Ban.handle HostEnvironment.system request
        | "users" -> Users.handle HostEnvironment.system request
        | "sudo" -> Sudo.handle HostEnvironment.system request
        | "content" -> Content.handle HostEnvironment.system request
        | "service" when fst (request.TryGetProperty "dockerFence") -> Services.handle firewalldEnvironment request
        | "service" -> Services.handle HostEnvironment.system request
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
            | :? DockerJob.BackendError as backendError -> Some backendError.Message
            | :? Swapfile.BackendError as backendError -> Some backendError.Message
            | :? Sshd.BackendError as backendError -> Some backendError.Message
            | :? Fail2Ban.BackendError as backendError -> Some backendError.Message
            | :? Users.BackendError as backendError -> Some backendError.Message
            | :? Sudo.BackendError as backendError -> Some backendError.Message
            | :? Content.BackendError as backendError -> Some backendError.Message
            | :? Services.BackendError as backendError -> Some backendError.Message
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
        if arguments.Length = 1 && arguments[0] = "firewalld-nft-table" then
            // Fixed read-only query, no request text or commands from the caller.
            try FirewalldNftTable.printTable ()
            with
            | :? DllNotFoundException | :? EntryPointNotFoundException -> 1
        elif arguments.Length = 5 && arguments[0] = "firewalld-docker-gate" then
            try
                let fence = FirewalldGateModel.parseArguments arguments[1] arguments[2] arguments[3] arguments[4]
                FirewalldDockerGate.verify firewalldEnvironment [ fence ]
                0
            with error ->
                reportFailure error
                1
        elif arguments.Length = 1 && arguments[0] = "firewalld-recover-postboot" then
            try
                verifyGlobalization ()
                Firewalld.recoverPendingPostBoot firewalldEnvironment
                Console.Out.WriteLine("{}")
                0
            with error ->
                reportFailure error
                1
        elif arguments.Length = 1 && arguments[0] = "firewalld-recover-boot" then
            try
                verifyGlobalization ()
                Firewalld.recoverPendingBoot firewalldEnvironment
                Console.Out.WriteLine("{}")
                0
            with error ->
                reportFailure error
                1
        elif arguments.Length = 1 && arguments[0] = "firewalld-recover" then
            try
                verifyGlobalization ()
                Firewalld.recoverPending firewalldEnvironment
                Console.Out.WriteLine("{}")
                0
            with error ->
                reportFailure error
                1
        elif arguments.Length = 1 && arguments[0] = "--version" then
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
            | command when command = "apt" || command = "ufw" || command = "firewalld" || command = "traefik" || command = "docker" || command = "docker-job" || command = "swapfile" || command = "sshd" || command = "fail2ban" || command = "users" || command = "sudo" || command = "content" || command = "service" ->
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
