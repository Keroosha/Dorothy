namespace Dorothy.TestFixture

open System
open System.Collections.Generic
open System.Collections.Immutable
open System.IO
open System.Text
open System.Threading
open System.Threading.Tasks
open Dorothy.DSL
open Pulumi

type private TrackingStream(bytes: byte array, onDispose: unit -> unit) =
    inherit MemoryStream(bytes, false)
    let mutable disposed = false

    override this.Dispose(disposing: bool) =
        if disposing && not disposed then
            disposed <- true
            onDispose ()
        base.Dispose(disposing)

module Program =
    let private requiredEnvironment name =
        match Environment.GetEnvironmentVariable(name) with
        | null -> failwith ("Missing test environment variable: " + name)
        | value -> value

    let private optionalEnvironment name fallback =
        match Environment.GetEnvironmentVariable(name) with
        | null -> fallback
        | value -> value

    let private decodedBytes name = requiredEnvironment name |> Convert.FromBase64String

    let private decodedText name = decodedBytes name |> Encoding.UTF8.GetString

    let private configuredValue (config: Config) name fallback =
        match config.Get(name) with
        | null -> fallback
        | value -> value

    let private configuredPackage (declaration: string) =
        let separator = declaration.IndexOf('=')
        if separator < 0 then
            { Name = declaration; Version = None }
        else
            packageVersion (declaration.Substring(0, separator)) (declaration.Substring(separator + 1))

    let private packageDeclarations (config: Config) =
        (configuredValue config "packages" "htop,mc").Split([| ',' |], StringSplitOptions.RemoveEmptyEntries ||| StringSplitOptions.TrimEntries)
        |> Array.map configuredPackage
        |> Array.toList

    let private connection () =
        let value = AptConnectionArgs()
        value.Address <- Input<string>.op_Implicit "192.0.2.1"
        value.User <- Input<string>.op_Implicit "root"
        value.Port <- Input<int>.op_Implicit 22
        value

    let private certificateMap () =
        let values = Dictionary<string, string>()
        values.Add("certificatePem", decodedText "TRAEFIK_CERTIFICATE_PEM_B64")
        values.Add("privateKeyPem", decodedText "TRAEFIK_PRIVATE_KEY_PEM_B64")
        values.Add("fingerprint", requiredEnvironment "TRAEFIK_CERTIFICATE_FINGERPRINT")
        let certificates = Dictionary<string, Dictionary<string, string>>()
        certificates.Add("example", values)
        certificates

    let private createTraefikResource (config: Config) =
        let entryPoints = Dictionary<string, int>()
        entryPoints.Add("websecure", 443)

        let resolvers = Dictionary<string, TraefikResolverArgs>()

        let tls = TraefikRouterTlsArgs()
        tls.Kind <- Input<string>.op_Implicit "provided"
        tls.Name <- Input<string>.op_Implicit "example"
        let router = TraefikRouterArgs()
        router.Host <- Input<string>.op_Implicit "example.org"
        router.EntryPoint <- Input<string>.op_Implicit "websecure"
        router.Backend <- Input<string>.op_Implicit (configuredValue config "backend" "http://127.0.0.1:12345")
        router.Tls <- Input<TraefikRouterTlsArgs>.op_Implicit tls
        let routers = Dictionary<string, TraefikRouterArgs>()
        routers.Add("example", router)

        let certificate = TraefikCertificateArgs()
        certificate.CertificatePem <- Input<string>.op_Implicit (decodedText "TRAEFIK_CERTIFICATE_PEM_B64")
        certificate.PrivateKeyPem <- Input<string>.op_Implicit (decodedText "TRAEFIK_PRIVATE_KEY_PEM_B64")
        certificate.Fingerprint <- Input<string>.op_Implicit (requiredEnvironment "TRAEFIK_CERTIFICATE_FINGERPRINT")
        let certificateValues = Dictionary<string, TraefikCertificateArgs>()
        certificateValues.Add("example", certificate)
        let secretCertificates = Output.CreateSecret(certificateValues)

        let args = TraefikArgs()
        args.Connection <- Input<AptConnectionArgs>.op_Implicit (connection ())
        if optionalEnvironment "UNKNOWN_ENTRYPOINT_MODE" "off" = "on" then
            let sourceHost =
                sshHost "unknown-entrypoint-source" {
                    Address "192.0.2.1"
                    User "root"
                    debian {
                        apt { "ca-certificates" }
                    }
                }
            let packageSet = Host.deploy sourceHost
            let unknownPort =
                packageSet.InstalledVersions.Apply<int>(
                    Func<ImmutableDictionary<string, string>, int>(fun _ -> 443)
                )
            let entryPointInputs = InputMap<int>()
            entryPointInputs.Add("websecure", Input<int>.op_Implicit 443)
            entryPointInputs.Add("dynamic", Input<int>.op_Implicit unknownPort)
            args.EntryPoints <- entryPointInputs
        else
            args.EntryPoints <- InputMap<int>.op_Implicit entryPoints
        args.Resolvers <- InputMap<TraefikResolverArgs>.op_Implicit resolvers
        args.Routers <- InputMap<TraefikRouterArgs>.op_Implicit routers
        args.Certificates <- InputMap<TraefikCertificateArgs>.op_Implicit secretCertificates
        args.AdminPort <- Input<int>.op_Implicit (int (configuredValue config "adminPort" "19080"))
        TraefikInstance("sandbox", args) |> ignore

    let private createAptScenario (config: Config) =
        let packages = packageDeclarations config
        let host =
            sshHost "sandbox" {
                Address "192.0.2.1"
                User "root"
                debian {
                    apt {
                        yield! packages
                    }
                }
            }
        Host.deploy host |> ignore

    let private createUfwScenario (config: Config) =
        let port = int (configuredValue config "rulePort" "443")
        let host =
            sshHost "sandbox" {
                Address "192.0.2.1"
                User "root"
                debian {
                    ufw {
                        DefaultIn Deny
                        DefaultOut Allow
                        Enabled true
                        allow {
                            toPort 22
                            proto Tcp
                        }
                        allow {
                            toPort port
                            proto Tcp
                        }
                    }
                }
            }
        Host.deploy host |> ignore

    let private createUfwRawScenario () =
        let host =
            sshHost "sandbox" {
                Address "192.0.2.1"
                User "root"
                debian {
                    ufw {
                        DefaultIn Deny
                        DefaultOut Allow
                        Enabled true
                        allow { toPort 22; proto Tcp }
                        raw "allow in 443/tcp comment injected"
                    }
                }
            }
        Host.deploy host |> ignore

    let private createUnknownSource () =
        let sourceHost =
            sshHost "unknown-output-source" {
                Address "192.0.2.1"
                User "root"
                debian {
                    apt { "ca-certificates" }
                }
            }
        Host.deploy sourceHost

    let private streamFactory (streamCreations: int ref) (streamDisposals: int ref) =
        let bytes =
            if optionalEnvironment "PFX_PASSWORD_MODE" "valid" = "multiple" then
                decodedBytes "PFX_MULTIPLE_B64"
            else
                decodedBytes "PFX_STREAM_B64"
        fun (_: CancellationToken) ->
            streamCreations.Value <- streamCreations.Value + 1
            File.AppendAllText(requiredEnvironment "STREAM_MARKER_PATH", "opened;")
            let stream =
                new TrackingStream(bytes, fun () ->
                    streamDisposals.Value <- streamDisposals.Value + 1
                    File.AppendAllText(requiredEnvironment "STREAM_MARKER_PATH", "disposed;"))
            Task.FromResult<Stream>(stream)

    let private pemInputs () =
        let keyMode = optionalEnvironment "PEM_KEY_MODE" "encrypted"
        let chain, key =
            match keyMode with
            | "expired" -> decodedText "PEM_EXPIRED_CHAIN_B64", decodedText "PEM_EXPIRED_KEY_B64"
            | "future" -> decodedText "PEM_FUTURE_CHAIN_B64", decodedText "PEM_FUTURE_KEY_B64"
            | "client-auth" -> decodedText "PEM_CLIENT_AUTH_CHAIN_B64", decodedText "PEM_CLIENT_AUTH_KEY_B64"
            | "wrong" -> decodedText "PEM_CHAIN_B64", decodedText "PEM_WRONG_KEY_B64"
            | _ -> decodedText "PEM_CHAIN_B64", decodedText "PEM_ENCRYPTED_KEY_B64"
        let chain = optionalEnvironment "PEM_CHAIN_OVERRIDE_B64" "" |> function
            | "" -> chain
            | value -> Convert.FromBase64String(value) |> Encoding.UTF8.GetString
        chain, key

    let private createTlsScenario (summary: Output<string> ref) =
        let streamCreations = ref 0
        let streamDisposals = ref 0
        let pemPath = requiredEnvironment "PEM_CERT_PATH"
        if File.Exists(pemPath) then failwith "The test PEM file must be absent until after DSL construction."

        let pemChain, pemKey = pemInputs ()
        let streamContent = Content.stream(streamFactory streamCreations streamDisposals)
        let pemPasswordMode = optionalEnvironment "PEM_PASSWORD_MODE" "valid"
        let pemCertificateSpec =
            match pemPasswordMode with
            | "missing" ->
                pemCertificate "encrypted" {
                    chain (Content.file pemPath)
                    privateKey (Content.pem(Output.CreateSecret(pemKey)))
                }
            | _ ->
                let pemPassword =
                    if pemPasswordMode = "wrong" then "not-the-password" else requiredEnvironment "PEM_PASSWORD"
                pemCertificate "encrypted" {
                    chain (Content.file pemPath)
                    privateKey (Content.pem(Output.CreateSecret(pemKey)))
                    password (Output.CreateSecret(pemPassword))
                }

        let pfxPasswordMode = optionalEnvironment "PFX_PASSWORD_MODE" "valid"
        let pfxSpec =
            match pfxPasswordMode with
            | "missing" ->
                pkcs12Certificate "stream" {
                    bundle streamContent
                }
            | "multiple" ->
                pkcs12Certificate "stream" {
                    bundle streamContent
                    password (Output.CreateSecret "multi-key-test-password")
                }
            | _ ->
                let pfxPassword =
                    if pfxPasswordMode = "wrong" then "not-the-password" else requiredEnvironment "PFX_PASSWORD"
                pkcs12Certificate "stream" {
                    bundle streamContent
                    password (Output.CreateSecret pfxPassword)
                }

        let inlineCertificate =
            pemCertificate "inline" {
                chain (Content.base64(requiredEnvironment "INLINE_CHAIN_B64"))
                privateKey (Content.pem(decodedText "INLINE_KEY_B64"))
            }
        let base64Certificate =
            pkcs12Certificate "base64" {
                bundle (Content.base64(Output.CreateSecret(requiredEnvironment "PFX_BASE64_B64")))
                password (requiredEnvironment "PFX_BASE64_PASSWORD")
            }
        let wildcardCertificate =
            pkcs12Certificate "wildcard" {
                bundle (Content.base64(Output.CreateSecret(requiredEnvironment "PFX_WILDCARD_B64")))
                password (Output.CreateSecret(requiredEnvironment "PFX_WILDCARD_PASSWORD"))
            }
        let resolver =
            acmeResolver "test-acme" {
                email (Output.CreateSecret "admin@example.test")
                challenge (Http01 "web")
                caServer (Output.CreateSecret "https://acme.example.test/directory")
            }
        let conflicts =
            if optionalEnvironment "CONFLICT_MODE" "off" = "on" then
                [ pemCertificate "conflict" {
                    chain (Content.base64(requiredEnvironment "INLINE_CHAIN_B64"))
                    privateKey (Content.pem(decodedText "INLINE_KEY_B64"))
                  } ]
            else
                []

        let unknownCertificate =
            if optionalEnvironment "UNKNOWN_MODE" "off" = "on" then
                let packageSet = createUnknownSource ()
                let unknownOutput =
                    packageSet.InstalledVersions.Apply<string>(
                        Func<ImmutableDictionary<string, string>, string>(fun _ -> "unknown certificate input")
                    )
                let secretUnknownOutput = Output.CreateSecret<string>(unknownOutput)
                Some(
                    pemCertificate "unknown" {
                        chain (Content.pem secretUnknownOutput)
                        privateKey streamContent
                    }
                )
            else
                None

        let normalSpec =
            traefik {
                entryPoint "web" { listen 8080 }
                resolver
                inlineCertificate
                pemCertificateSpec
                pfxSpec
                base64Certificate
                wildcardCertificate
                router "inline" {
                    host "inline.example.test"
                    entryPoint "web"
                    backend "http://127.0.0.1:8081"
                    tls (Provided inlineCertificate)
                }
                router "encrypted" {
                    host (Output.CreateSecret(requiredEnvironment "PEM_HOST"))
                    entryPointOutput (Output.CreateSecret "web")
                    backend (Output.Create "http://127.0.0.1:8082")
                    tls (Provided pemCertificateSpec)
                }
                router "stream" {
                    host "stream.example.test"
                    entryPoint "web"
                    backend "http://127.0.0.1:8083"
                    tls (Provided pfxSpec)
                }
                router "base64" {
                    host "base64.example.test"
                    entryPoint "web"
                    backend "http://127.0.0.1:8084"
                    tls (Provided base64Certificate)
                }
                router "wildcard" {
                    host "service.wildcard.example.test"
                    entryPoint "web"
                    backend "http://127.0.0.1:8086"
                    tls (Provided wildcardCertificate)
                }
                router "acme" {
                    host "acme.example.test"
                    entryPoint "web"
                    backend "http://127.0.0.1:8085"
                    tls (Acme resolver)
                }
                yield! conflicts
            }

        let unknownSpec =
            unknownCertificate
            |> Option.map (fun certificate ->
                traefik {
                    entryPoint "web" { listen 8080 }
                    certificate
                })
        let specification = unknownSpec |> Option.defaultValue normalSpec

        File.WriteAllText(pemPath, pemChain)
        let resolved = specification.Resolve(CancellationToken.None)
        let certificateSummary =
            resolved.Certificates.Apply<string>(
                Func<ImmutableDictionary<string, NormalizedCertificate>, string>(fun certificates ->
                    for certificate in certificates.Values do
                        if not (certificate.CertificatePem.StartsWith("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal)) then
                            failwith "Resolved certificate chain is not normalized PEM."
                        if certificate.Name = "encrypted"
                           && certificate.CertificatePem.Split([| "-----BEGIN CERTIFICATE-----" |], StringSplitOptions.None).Length <> 4 then
                            failwith "The supplied certificate chain must contain its leaf, intermediate, and root."
                        if not (certificate.PrivateKeyPem.StartsWith("-----BEGIN PRIVATE KEY-----", StringComparison.Ordinal)) then
                            failwith "Resolved private key is not normalized unencrypted PKCS#8 PEM."
                        if certificate.Fingerprint.Length <> 64
                           || not (certificate.Fingerprint |> Seq.forall (fun character -> (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'))) then
                            failwith "Resolved certificate fingerprint is not lowercase SHA-256 hex."
                    let fingerprints =
                        certificates.Values
                        |> Seq.map (fun certificate -> certificate.Name + "=" + certificate.Fingerprint)
                        |> Seq.sort
                        |> String.concat ","
                    let status = sprintf "%d|%d|%s" streamCreations.Value streamDisposals.Value fingerprints
                    File.WriteAllText(requiredEnvironment "STATUS_PATH", status)
                    status))
        summary.Value <- Output.CreateSecret<string>(certificateSummary)



    type InfrastructureStack() =
        inherit Stack()

        let certificateSummary = ref (Output.Create(String.Empty))

        do
            let config = Config()
            let scenario = config.Require("scenario")
            match scenario with
            | "empty" -> ()
            | "apt" -> createAptScenario config
            | "ufw" -> createUfwScenario config
            | "ufw-raw" -> createUfwRawScenario ()
            | "traefik" -> createTraefikResource config
            | "tls" -> createTlsScenario certificateSummary
            | "seed-secret" -> ()
            | other -> invalidArg "scenario" ("Unsupported test fixture scenario '" + other + "'.")

        [<Output("certificateSummary")>]
        member _.CertificateSummary = certificateSummary.Value

        [<Output("certificateMap")>]
        member _.CertificateMap =
            match Environment.GetEnvironmentVariable("TRAEFIK_CERTIFICATE_PEM_B64"), Environment.GetEnvironmentVariable("TRAEFIK_PRIVATE_KEY_PEM_B64"), Environment.GetEnvironmentVariable("TRAEFIK_CERTIFICATE_FINGERPRINT") with
            | null, _, _
            | _, null, _
            | _, _, null -> Output.CreateSecret(Dictionary<string, Dictionary<string, string>>())
            | _ -> Output.CreateSecret(certificateMap ())

    [<EntryPoint>]
    let main _ =
        Deployment.RunAsync<InfrastructureStack>()
        |> fun run -> run.GetAwaiter().GetResult()
