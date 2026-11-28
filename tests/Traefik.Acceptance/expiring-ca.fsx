// No private key leaves this process. Use only for the disposable stored-state acceptance case.
open System
open System.IO
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates

let create path =
    use key = ECDsa.Create(ECCurve.NamedCurves.nistP256)
    let request = CertificateRequest("CN=temporary acceptance CA", key, HashAlgorithmName.SHA256)
    request.CertificateExtensions.Add(X509BasicConstraintsExtension(true, false, 0, true))
    request.CertificateExtensions.Add(X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true))
    let now = DateTimeOffset.UtcNow
    use cert = request.CreateSelfSigned(now.AddMinutes(-1.), now.AddSeconds(45.))
    File.WriteAllText(path, cert.ExportCertificatePem())
create fsi.CommandLineArgs[1]
