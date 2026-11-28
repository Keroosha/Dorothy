// Offline only: run against the compiled review consumer AND managed helper (see CI).
open System
open System.IO
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Text.Json
open System.Text.Json.Nodes
open System.Threading
open Dorothy.HostHelper
open Dorothy.Traefik.Acceptance.Review
open Pulumi.Utilities

let work = Directory.CreateTempSubdirectory("dorothy-issuer-check-")
try
    use key = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let ca = CertificateRequest("CN=Offline Fixture CA", key, HashAlgorithmName.SHA256)
    ca.CertificateExtensions.Add(X509BasicConstraintsExtension(true, false, 0, true))
    use cert = ca.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1.), DateTimeOffset.UtcNow.AddDays(1.))
    let caFile = Path.Combine(work.FullName, "ca.pem")
    File.WriteAllText(caFile, cert.ExportCertificatePem())
    let token = Path.Combine(work.FullName, "synthetic-input")
    File.WriteAllText(token, "b2ZmbGluZQ==")
    Environment.SetEnvironmentVariable("CLIENT_CA_FILE", caFile)
    Environment.SetEnvironmentVariable("DNS_TSIG_SECRET_FILE", token)
    let paths: Traefik.RuntimePaths =
        { ConfigDir = work.FullName; StateDir = work.FullName; InstallDir = work.FullName; UnitPath = Path.Combine(work.FullName, "unit") }
    for phase, expected in ["review-tls-mtls", "https://localhost:14000/dir"; "review-tls-issuer-switch", "https://localhost:14001/dir"] do
        let spec = (ReviewTls.createHost phase).Traefik.Value.Resolve(CancellationToken.None)
        let text = OutputUtilities.GetValueAsync(spec.Configuration.Value).GetAwaiter().GetResult()
        let request = JsonNode.Parse("""{"operation":"apply","ownerId":"offline-fixture","entryPoints":{},"routers":{},"resolvers":{},"certificates":{},"adminPort":19080}""").AsObject()
        request["configuration"] <- JsonNode.Parse(text)
        use envelope = JsonDocument.Parse(request.ToJsonString())
        use rendered = JsonDocument.Parse(Traefik.renderStaticConfig envelope.RootElement paths "")
        let resolvers = rendered.RootElement.GetProperty("certificatesResolvers")
        let acme = resolvers.GetProperty("review-acme").GetProperty("acme")
        let mutable directory = Unchecked.defaultof<JsonElement>
        if Seq.length (resolvers.EnumerateObject()) <> 1 || not (acme.TryGetProperty("caServer", &directory))
           || directory.GetString() <> expected || acme.GetProperty("dnsChallenge").GetProperty("provider").GetString() <> "dnsupdate" then
            failwithf "%s: missing or incorrect local ACME issuer/challenge in effective static configuration." phase
        printfn "%s: effective directory %s; local DNS fixture." phase expected
finally
    work.Delete(true)
