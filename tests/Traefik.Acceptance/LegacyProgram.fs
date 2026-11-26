namespace Dorothy.Traefik.Acceptance

open System
open System.IO
open Dorothy.DSL
open Pulumi

module LegacyProgram =
    let private requiredEnvironment name =
        match Environment.GetEnvironmentVariable(name) with
        | null -> invalidOp "A private legacy certificate fixture is missing."
        | value -> value

    let private configuredValue (config: Config) name fallback =
        match config.Get(name) with
        | null -> fallback
        | value -> value

    let private createHost () =
        let config = Config()
        let backendUrl = configuredValue config "backend" "http://127.0.0.1:8080"
        let certificate =
            pemCertificate "example" {
                chain (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_LEGACY_CERT_FILE"))
                privateKey (Content.file (requiredEnvironment "TRAEFIK_ACCEPTANCE_LEGACY_KEY_FILE"))
            }

        sshHost "sandbox" {
            Address "192.0.2.1"
            User "root"
            Port 22
            debian {
                traefik {
                    entryPoint "websecure" { listen 443 }
                    certificate
                    router "example" {
                        host "example.org"
                        entryPoint "websecure"
                        backend backendUrl
                        tls (TraefikTlsMode.Provided certificate)
                    }
                    adminPort 19080
                }
            }
        }

    type InfrastructureStack() =
        inherit Stack()
        do Host.deploy (createHost ()) |> ignore

    [<EntryPoint>]
    let main _ =
        Deployment.RunAsync<InfrastructureStack>()
        |> fun run -> run.GetAwaiter().GetResult()
