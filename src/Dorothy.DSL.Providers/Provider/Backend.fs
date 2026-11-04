namespace Dorothy.DSL.Provider

open System
open System.Diagnostics
open System.IO
open System.Text
open System.Text.Json
open System.Security.Cryptography
open System.Threading
open System.Threading.Tasks

type SshConnection =
    { Address: string
      User: string
      Port: int
      IdentityFile: string option }


type NativeHelperUnavailableException(message: string) =
    inherit InvalidOperationException(message)

type NativeHelperBackendException(message: string) =
    inherit InvalidOperationException(message)

type AptSnapshot =
    { InstalledVersions: Map<string, string>
      ManagedPackages: string list }

module SshTransport =
    let private validateConnection (connection: SshConnection) =
        let hasInvalidCharacter (value: string) =
            value |> Seq.exists (fun character -> Char.IsControl character || Char.IsWhiteSpace character)

        if String.IsNullOrWhiteSpace connection.Address then
            invalidArg "connection" "SSH address must not be empty."

        if String.IsNullOrWhiteSpace connection.User then
            invalidArg "connection" "SSH user must not be empty."

        if connection.Address.StartsWith("-", StringComparison.Ordinal)
           || connection.Address.Contains('@')
           || hasInvalidCharacter connection.Address then
            invalidArg "connection" "SSH address contains unsupported characters."

        if connection.User.StartsWith("-", StringComparison.Ordinal)
           || connection.User.Contains('@')
           || connection.User.Contains('/')
           || hasInvalidCharacter connection.User then
            invalidArg "connection" "SSH user contains unsupported characters."

        if connection.Port < 1 || connection.Port > 65535 then
            invalidArg "connection" "SSH port must be between 1 and 65535."

        match connection.IdentityFile with
        | Some path when String.IsNullOrWhiteSpace path || path.Contains('\000') ->
            invalidArg "connection" "SSH identityFile must be a non-empty local path."
        | _ -> ()

    let private createStartInfo (connection: SshConnection) (remoteCommand: string) (freshConnection: bool) =
        let startInfo = ProcessStartInfo()
        startInfo.FileName <- "ssh"
        startInfo.UseShellExecute <- false
        startInfo.RedirectStandardInput <- true
        startInfo.RedirectStandardOutput <- true
        startInfo.RedirectStandardError <- true
        startInfo.CreateNoWindow <- true

        let addArgument value = startInfo.ArgumentList.Add(value)

        addArgument "-T"
        addArgument "-o"
        addArgument "BatchMode=yes"
        addArgument "-o"
        addArgument "StrictHostKeyChecking=yes"
        addArgument "-o"
        addArgument "ConnectTimeout=15"
        if freshConnection then
            addArgument "-o"
            addArgument "ControlMaster=no"
            addArgument "-o"
            addArgument "ControlPath=none"
        addArgument "-p"
        addArgument (string connection.Port)

        match connection.IdentityFile with
        | Some path ->
            addArgument "-i"
            addArgument path
            addArgument "-o"
            addArgument "IdentitiesOnly=yes"
        | None -> ()

        addArgument (connection.User + "@" + connection.Address)
        addArgument remoteCommand
        startInfo

    let private tryTerminate (sshProcess: Process) =
        try
            if not sshProcess.HasExited then
                sshProcess.Kill(true)
        with _ -> ()

    let private drainAfterTermination
        (sshProcess: Process)
        (stdoutTask: Task<string>)
        (stderrTask: Task<string>)
        =
        task {
            try
                do! sshProcess.WaitForExitAsync(CancellationToken.None)
            with _ -> ()

            let mutable standardOutput = ""
            let mutable standardError = ""

            try
                let! output = stdoutTask
                standardOutput <- output
            with _ -> ()

            try
                let! error = stderrTask
                standardError <- error
            with _ -> ()

            return standardOutput, standardError
        }

    let private describeRemoteFailure
        (operationName: string)
        (connection: SshConnection)
        (exitCode: int)
        (standardOutput: string)
        (standardError: string)
        =
        let diagnostic =
            if String.IsNullOrWhiteSpace standardError then
                if String.IsNullOrWhiteSpace standardOutput then
                    sprintf "remote command exited with code %d" exitCode
                else
                    standardOutput.Trim()
            else
                standardError.Trim()

        let prerequisiteHint =
            if diagnostic.Contains("sudo: not found", StringComparison.OrdinalIgnoreCase)
               || diagnostic.Contains("sudo: command not found", StringComparison.OrdinalIgnoreCase)
               || diagnostic.Contains("a password is required", StringComparison.OrdinalIgnoreCase) then
                " Remote prerequisite missing: install sudo and grant non-interactive privilege to the SSH user; the provider will not install it."
            else
                ""

        sprintf
            "Remote %s operation on %s@%s:%d failed (exit %d): %s%s"
            operationName
            connection.User
            connection.Address
            connection.Port
            exitCode
            diagnostic
            prerequisiteHint

    let private runRemoteCommand
        (connection: SshConnection)
        (operationName: string)
        (remoteCommand: string)
        (standardInput: Stream option)
        (cancellationToken: CancellationToken)
        (freshConnection: bool)
        =
        task {
            validateConnection connection
            let startInfo = createStartInfo connection remoteCommand freshConnection
            use sshProcess = new Process()
            sshProcess.StartInfo <- startInfo

            try
                if not (sshProcess.Start()) then
                    raise (InvalidOperationException("The local OpenSSH process did not start."))
            with error ->
                raise (InvalidOperationException("Could not start the local OpenSSH client 'ssh'.", error))

            let stdoutTask = sshProcess.StandardOutput.ReadToEndAsync()
            let stderrTask = sshProcess.StandardError.ReadToEndAsync()

            try
                match standardInput with
                | Some input ->
                    do!
                        input.CopyToAsync(
                            sshProcess.StandardInput.BaseStream,
                            81920,
                            cancellationToken
                        )
                | None -> ()

                sshProcess.StandardInput.Close()
                do! sshProcess.WaitForExitAsync(cancellationToken)
            with error ->
                try
                    sshProcess.StandardInput.Close()
                with _ -> ()

                tryTerminate sshProcess
                let! (standardOutput, standardError) =
                    drainAfterTermination sshProcess stdoutTask stderrTask

                match error with
                | :? OperationCanceledException ->
                    raise (
                        OperationCanceledException(
                            sprintf "SSH operation was cancelled; terminating the local SSH process does not roll back remote %s work." operationName,
                            error,
                            cancellationToken
                        )
                    )
                | _ ->
                    let exitCode =
                        if sshProcess.HasExited then
                            sshProcess.ExitCode
                        else
                            -1

                    raise (
                        InvalidOperationException(
                            describeRemoteFailure operationName connection exitCode standardOutput standardError,
                            error
                        )
                    )

            let! standardOutput = stdoutTask
            let! standardError = stderrTask

            if sshProcess.ExitCode <> 0 then
                let diagnostic = standardError.Trim()
                let backendErrorPrefix = "keroosha-iac-helper: backend error: "

                if diagnostic.StartsWith(backendErrorPrefix, StringComparison.Ordinal) then
                    let message = diagnostic.Substring(backendErrorPrefix.Length)

                    if not (String.IsNullOrWhiteSpace message) then
                        raise (NativeHelperBackendException(message))

                raise (
                    InvalidOperationException(
                        describeRemoteFailure operationName connection sshProcess.ExitCode standardOutput standardError
                    )
                )

            return standardOutput
        }

    let private quotePosix (value: string) =
        "'" + value.Replace("'", "'\"'\"'") + "'"

    let private runPrivilegedShell (connection: SshConnection) (script: string) =
        let shellCommand = "sh -c " + quotePosix script

        if connection.User = "root" then
            shellCommand
        else
            "sudo -n -- " + shellCommand

    let private remoteArchitecture (connection: SshConnection) (cancellationToken: CancellationToken) =
        task {
            let! output =
                runRemoteCommand
                    connection
                    "native helper architecture detection"
                    "uname -s && uname -m"
                    None
                    cancellationToken
                    false

            let lines =
                output.Trim().Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
                |> Array.map (fun line -> line.Trim())

            match lines with
            | [| "Linux"; "x86_64" |] -> return "linux-x64"
            | [| "Linux"; "aarch64" |] -> return "linux-arm64"
            | [| "Linux"; architecture |] ->
                return raise (NativeHelperUnavailableException(sprintf "Unsupported remote Linux architecture '%s'; only x64 and arm64 are supported." architecture))
            | _ ->
                return raise (NativeHelperUnavailableException("The remote host did not report a supported Linux platform."))
        }

    let private helperArtifact (rid: string) =
        let helperPath =
            Path.Combine(AppContext.BaseDirectory, "helper", rid, "keroosha-iac-helper")

        if not (File.Exists helperPath) then
            raise (
                NativeHelperUnavailableException(
                    sprintf
                        "Native helper artifact for target RID '%s' is missing at '%s'. Package it with `bash scripts/publish-host-helper.sh %s` and rebuild the provider; no interpreter fallback is available."
                        rid
                        helperPath
                        rid
                )
            )

        use stream = File.OpenRead helperPath
        let header = Array.zeroCreate<byte> 20
        let mutable headerLength = 0
        let mutable reachedEnd = false

        while headerLength < header.Length && not reachedEnd do
            let readLength = stream.Read(header, headerLength, header.Length - headerLength)

            if readLength = 0 then
                reachedEnd <- true
            else
                headerLength <- headerLength + readLength

        if headerLength <> header.Length
           || header[0] <> 0x7Fuy
           || header[1] <> byte 'E'
           || header[2] <> byte 'L'
           || header[3] <> byte 'F'
           || header[4] <> 2uy
           || header[5] <> 1uy then
            raise (NativeHelperUnavailableException(sprintf "Native helper artifact for target RID '%s' is not a 64-bit little-endian ELF executable." rid))

        let machine = int header[18] ||| (int header[19] <<< 8)
        let expectedMachine = if rid = "linux-x64" then 62 else 183

        if machine <> expectedMachine then
            raise (NativeHelperUnavailableException(sprintf "Native helper artifact for target RID '%s' has an incompatible ELF architecture." rid))

        stream.Position <- 0L
        let digestBytes = SHA256.HashData(stream)
        let digest = Convert.ToHexString(digestBytes).ToLowerInvariant()
        helperPath, digest

    let private cacheCheckScript (rid: string) (digest: string) =
        String.concat
            "\n"
            [ "set -eu"
              "base=/var/cache/keroosha-iac"
              "ensure_dir() {"
              "  path=$1"
              "  if [ -L \"$path\" ]; then exit 73; fi"
              "  if [ ! -e \"$path\" ]; then mkdir -m 0700 -- \"$path\"; fi"
              "  [ -d \"$path\" ] || exit 73"
              "  chown 0:0 -- \"$path\""
              "  chmod 0700 -- \"$path\""
              "  [ \"$(stat -c '%u:%g:%a' -- \"$path\")\" = \"0:0:700\" ] || exit 73"
              "}"
              "ensure_dir \"$base\""
              "ensure_dir \"$base/helper\""
              sprintf "ensure_dir \"$base/helper/%s\"" rid
              sprintf "hash='%s'" digest
              sprintf "target=\"$base/helper/%s/$hash\"" rid
              "if [ -L \"$target\" ]; then exit 73; fi"
              "if [ -e \"$target\" ] && [ ! -f \"$target\" ]; then exit 73; fi"
              "if [ -f \"$target\" ] && [ \"$(stat -c '%u:%g:%a' -- \"$target\")\" = \"0:0:755\" ] && printf '%s  %s\\n' \"$hash\" \"$target\" | sha256sum -c - >/dev/null 2>&1; then"
              "  echo present"
              "else"
              "  echo missing"
              "fi" ]

    let private cacheInstallScript (rid: string) (digest: string) =
        String.concat
            "\n"
            [ "set -eu"
              "base=/var/cache/keroosha-iac"
              "ensure_dir() {"
              "  path=$1"
              "  if [ -L \"$path\" ]; then exit 73; fi"
              "  if [ ! -e \"$path\" ]; then mkdir -m 0700 -- \"$path\"; fi"
              "  [ -d \"$path\" ] || exit 73"
              "  chown 0:0 -- \"$path\""
              "  chmod 0700 -- \"$path\""
              "  [ \"$(stat -c '%u:%g:%a' -- \"$path\")\" = \"0:0:700\" ] || exit 73"
              "}"
              "ensure_dir \"$base\""
              "ensure_dir \"$base/helper\""
              sprintf "ensure_dir \"$base/helper/%s\"" rid
              sprintf "hash='%s'" digest
              sprintf "target=\"$base/helper/%s/$hash\"" rid
              "if [ -L \"$target\" ]; then exit 73; fi"
              "if [ -e \"$target\" ] && [ ! -f \"$target\" ]; then exit 73; fi"
              sprintf "temporary=$(mktemp \"$base/helper/%s/.helper.XXXXXX\")" rid
              "cleanup() { rm -f -- \"$temporary\"; }"
              "trap cleanup EXIT HUP INT TERM"
              "cat > \"$temporary\""
              "printf '%s  %s\\n' \"$hash\" \"$temporary\" | sha256sum -c - >/dev/null"
              "chown 0:0 -- \"$temporary\""
              "chmod 0755 -- \"$temporary\""
              "mv -f -- \"$temporary\" \"$target\""
              "trap - EXIT HUP INT TERM"
              "echo installed" ]

    let private ensureRemoteHelper
        (connection: SshConnection)
        (operationName: string)
        (rid: string)
        (helperPath: string)
        (digest: string)
        (cancellationToken: CancellationToken)
        =
        task {
            let checkCommand =
                runPrivilegedShell connection (cacheCheckScript rid digest)

            let! cacheState =
                runRemoteCommand
                    connection
                    "native helper cache verification"
                    checkCommand
                    None
                    cancellationToken
                    false

            match cacheState.Trim() with
            | "present" -> ()
            | "missing" ->
                use binary = File.OpenRead helperPath
                let installCommand =
                    runPrivilegedShell connection (cacheInstallScript rid digest)

                let! _ =
                    runRemoteCommand
                        connection
                        (operationName + " native helper installation")
                        installCommand
                        (Some binary)
                        cancellationToken
                        false

                ()
            | _ ->
                raise (InvalidOperationException("The remote native helper cache returned an invalid status."))
        }

    let private ensureIcuRuntime
        (connection: SshConnection)
        (cancellationToken: CancellationToken)
        =
        task {
            let checkCommand =
                "icu_libraries=$(/sbin/ldconfig -p 2>/dev/null || true)\nif printf '%s\\n' \"$icu_libraries\" | /usr/bin/grep -q 'libicuuc.so' && printf '%s\\n' \"$icu_libraries\" | /usr/bin/grep -q 'libicui18n.so'; then echo present; else echo missing; fi"

            let! status =
                runRemoteCommand
                    connection
                    "native helper ICU prerequisite check"
                    checkCommand
                    None
                    cancellationToken
                    false

            match status.Trim() with
            | "present" -> ()
            | "missing" ->
                let installCommand =
                    String.concat
                        "\n"
                        [ "set -eu"
                          "has_icu_runtime() {"
                          "  icu_libraries=$(/sbin/ldconfig -p 2>/dev/null || true)"
                          "  printf '%s\\n' \"$icu_libraries\" | /usr/bin/grep -q 'libicuuc.so' && printf '%s\\n' \"$icu_libraries\" | /usr/bin/grep -q 'libicui18n.so'"
                          "}"
                          "if has_icu_runtime; then echo present; exit 0; fi"
                          "if [ ! -r /etc/os-release ]; then echo unsupported; exit 0; fi"
                          ". /etc/os-release"
                          "if [ \"${ID:-}\" != debian ] || [ \"${VERSION_ID:-}\" != 13 ]; then echo unsupported; exit 0; fi"
                          "if ! command -v apt-get >/dev/null 2>&1; then echo unavailable; exit 0; fi"
                          "export DEBIAN_FRONTEND=noninteractive"
                          "apt-get update 1>&2"
                          "apt-get install -y --no-install-recommends --no-remove libicu76 1>&2"
                          "/sbin/ldconfig"
                          "if has_icu_runtime; then echo installed; else echo missing; fi" ]
                    |> runPrivilegedShell connection

                let! installStatus =
                    runRemoteCommand
                        connection
                        "native helper ICU prerequisite installation"
                        installCommand
                        None
                        cancellationToken
                        false

                match installStatus.Trim() with
                | "present"
                | "installed" -> ()
                | "unsupported" ->
                    raise (
                        NativeHelperUnavailableException(
                            "Compatible ICU runtime libraries (libicuuc and libicui18n) are required for full Unicode/IDN behavior. Automatic installation is supported only on Debian 13 (libicu76); install a compatible runtime manually on this host before resource operations."
                        )
                    )
                | "unavailable" ->
                    raise (
                        NativeHelperUnavailableException(
                            "A compatible ICU runtime is missing; automatic Debian 13 installation requires apt-get to install libicu76."
                        )
                    )
                | "missing" ->
                    raise (
                        NativeHelperUnavailableException(
                            "The Debian 13 libicu76 package was installed, but ldconfig still cannot find both required ICU runtime libraries."
                        )
                    )
                | _ ->
                    raise (NativeHelperUnavailableException("Could not verify or install the required ICU runtime package."))
            | _ ->
                raise (NativeHelperUnavailableException("Could not verify the required Debian ICU runtime package."))
        }

    let private verifyHelperProtocol
        (connection: SshConnection)
        (rid: string)
        (digest: string)
        (cancellationToken: CancellationToken)
        =
        task {
            let remotePath = sprintf "/var/cache/keroosha-iac/helper/%s/%s" rid digest
            let command =
                if connection.User = "root" then
                    sprintf "%s --version" remotePath
                else
                    sprintf "sudo -n -- %s --version" remotePath

            try
                let! reportedVersion =
                    runRemoteCommand
                        connection
                        "native helper protocol validation"
                        command
                        None
                        cancellationToken
                        false

                if reportedVersion.Trim() <> "keroosha-iac-helper protocol 1" then
                    raise (NativeHelperUnavailableException("The installed native helper does not report protocol version 1."))
            with
            | :? OperationCanceledException as error -> return raise error
            | :? NativeHelperUnavailableException as error -> return raise error
            | :? NativeHelperBackendException as error ->
                return raise (NativeHelperUnavailableException(error.Message))
            | :? InvalidOperationException as error when error.Message.Contains("libicu", StringComparison.OrdinalIgnoreCase) ->
                return
                    raise (
                        NativeHelperUnavailableException(
                            "The native helper could not load compatible ICU runtime libraries; on Debian 13 install libicu76. No resource operations were started."
                        )
                    )
            | error -> return raise error
        }

    let private runHelperWithOptions
        (connection: SshConnection)
        (helperCommand: string)
        (operationName: string)
        (payload: string)
        (cancellationToken: CancellationToken)
        (freshFinalConnection: bool)
        =
        task {
            if helperCommand <> "apt" && helperCommand <> "ufw" && helperCommand <> "traefik" && helperCommand <> "docker" && helperCommand <> "swapfile" && helperCommand <> "sshd" && helperCommand <> "fail2ban" && helperCommand <> "users" && helperCommand <> "sudo" then
                invalidArg "helperCommand" "Unsupported native helper operation."

            validateConnection connection
            let! rid = remoteArchitecture connection cancellationToken
            let helperPath, digest = helperArtifact rid
            do! ensureIcuRuntime connection cancellationToken
            do! ensureRemoteHelper connection operationName rid helperPath digest cancellationToken
            do! verifyHelperProtocol connection rid digest cancellationToken

            let remotePath = sprintf "/var/cache/keroosha-iac/helper/%s/%s" rid digest
            let remoteCommand =
                if connection.User = "root" then
                    sprintf "exec %s %s" remotePath helperCommand
                elif helperCommand = "sshd" then
                    sprintf "sudo -n -- env SSH_CONNECTION=\"${SSH_CONNECTION-}\" %s %s" remotePath helperCommand
                else
                    sprintf "sudo -n -- %s %s" remotePath helperCommand

            use requestStream = new MemoryStream(Encoding.UTF8.GetBytes(payload), false)

            return!
                runRemoteCommand
                    connection
                    operationName
                    remoteCommand
                    (Some requestStream)
                    cancellationToken
                    freshFinalConnection
        }

    let runHelper connection helperCommand operationName payload cancellationToken =
        runHelperWithOptions connection helperCommand operationName payload cancellationToken false

    let runHelperFreshConnection connection helperCommand operationName payload cancellationToken =
        runHelperWithOptions connection helperCommand operationName payload cancellationToken true

module AptBackend =
    let private serializePayload (operation: string) (writeFields: Utf8JsonWriter -> unit) =
        use stream = new MemoryStream()
        use writer = new Utf8JsonWriter(stream)
        writer.WriteStartObject()
        writer.WriteString("operation", operation)
        writeFields writer
        writer.WriteEndObject()
        writer.Flush()
        Encoding.UTF8.GetString(stream.GetBuffer(), 0, int stream.Length)

    let private readPayload (ownerId: string) (names: string list) =
        serializePayload "read" (fun writer ->
            writer.WriteString("ownerId", ownerId)
            writer.WriteStartArray("names")

            for name in names do
                writer.WriteStringValue(name)

            writer.WriteEndArray())

    let private applyPayload
        (ownerId: string)
        (previousNames: string list)
        (desiredVersions: Map<string, string option>)
        =
        serializePayload "apply" (fun writer ->
            writer.WriteString("ownerId", ownerId)
            writer.WriteStartArray("previousNames")

            for name in previousNames do
                writer.WriteStringValue(name)

            writer.WriteEndArray()
            writer.WriteStartObject("desiredVersions")

            for KeyValue(name, version) in desiredVersions do
                writer.WritePropertyName(name)

                match version with
                | Some exactVersion -> writer.WriteStringValue(exactVersion)
                | None -> writer.WriteNullValue()

            writer.WriteEndObject())
    let private parseSnapshot
        (expectedNames: Set<string>)
        (requireManagedExactly: bool)
        (requireAllInstalled: bool)
        (output: string)
        =
        try
            use document = JsonDocument.Parse(output)
            let root = document.RootElement

            if root.ValueKind <> JsonValueKind.Object then
                raise (FormatException("Remote result must be a JSON object."))

            let properties = root.EnumerateObject() |> Seq.toArray
            let propertyNames = properties |> Array.map (fun property -> property.Name) |> Set.ofArray
            let expectedProperties = Set.ofList [ "installedVersions"; "managedPackages" ]

            if properties.Length <> 2 || propertyNames <> expectedProperties then
                raise (FormatException("Remote result must contain only installedVersions and managedPackages."))

            let installedElement = root.GetProperty("installedVersions")

            if installedElement.ValueKind <> JsonValueKind.Object then
                raise (FormatException("Remote installedVersions must be a JSON object."))

            let managedElement = root.GetProperty("managedPackages")

            if managedElement.ValueKind <> JsonValueKind.Array then
                raise (FormatException("Remote managedPackages must be a JSON array."))

            let mutable managedPackages = []
            let mutable managedSet = Set.empty

            for item in managedElement.EnumerateArray() do
                if item.ValueKind <> JsonValueKind.String then
                    raise (FormatException("Remote managedPackages entries must be strings."))

                let packageName = item.GetString()

                if String.IsNullOrWhiteSpace packageName then
                    raise (FormatException("Remote managedPackages contains an empty package name."))

                if managedSet.Contains packageName then
                    raise (FormatException(sprintf "Remote managedPackages contains duplicate package %s." packageName))

                managedSet <- Set.add packageName managedSet
                managedPackages <- packageName :: managedPackages

            managedPackages <- List.rev managedPackages

            if not (Set.isSubset expectedNames managedSet) then
                raise (FormatException("Remote managedPackages omitted a previously owned package."))

            if requireManagedExactly && managedSet <> expectedNames then
                raise (FormatException("Remote apply result does not match the desired ownership set."))

            let mutable installedVersions: Map<string, string> = Map.empty

            for property in installedElement.EnumerateObject() do
                if installedVersions.ContainsKey property.Name then
                    raise (FormatException(sprintf "Remote result contains duplicate package %s." property.Name))

                if not (managedSet.Contains property.Name) then
                    raise (FormatException(sprintf "Remote result contains unowned package %s." property.Name))

                if property.Value.ValueKind <> JsonValueKind.String then
                    raise (FormatException(sprintf "Remote version for %s is not a string." property.Name))

                let version = property.Value.GetString()

                if String.IsNullOrWhiteSpace version then
                    raise (FormatException(sprintf "Remote result contains an empty version for %s." property.Name))

                installedVersions <- Map.add property.Name version installedVersions

            if requireAllInstalled && installedVersions.Count <> expectedNames.Count then
                raise (FormatException("Remote apply result omitted one or more desired packages."))

            { InstalledVersions = installedVersions
              ManagedPackages = managedPackages }
        with
        | :? JsonException as error ->
            raise (InvalidOperationException("Remote APT helper returned invalid JSON.", error))

    let private invoke
        (connection: SshConnection)
        (expectedNames: Set<string>)
        (requireManagedExactly: bool)
        (requireAllInstalled: bool)
        (payload: string)
        (cancellationToken: CancellationToken)
        =
        task {
            let! output = SshTransport.runHelper connection "apt" "APT" payload cancellationToken

            return
                parseSnapshot expectedNames requireManagedExactly requireAllInstalled output
        }

    let read
        (connection: SshConnection)
        (ownerId: string)
        (names: string list)
        (cancellationToken: CancellationToken)
        : Task<AptSnapshot> =
        invoke connection (Set.ofList names) false false (readPayload ownerId names) cancellationToken

    let apply
        (connection: SshConnection)
        (ownerId: string)
        (previousNames: string list)
        (desiredVersions: Map<string, string option>)
        (cancellationToken: CancellationToken)
        : Task<AptSnapshot> =
        let expectedNames = desiredVersions |> Map.toSeq |> Seq.map fst |> Set.ofSeq

        invoke
            connection
            expectedNames
            true
            true
            (applyPayload ownerId previousNames desiredVersions)
            cancellationToken
