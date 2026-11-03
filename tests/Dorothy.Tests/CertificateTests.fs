namespace Dorothy.Tests

open System
open System.IO
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Threading
open System.Threading.Tasks
open Dorothy.DSL
open NUnit.Framework
open Dorothy.Tests.TestSupport

[<TestFixture>]
type CertificateTests() =
    let normalized name (fixture: CertificateFixture) =
        { Name = name
          CertificatePem = fixture.ChainPem
          PrivateKeyPem = fixture.PrivateKeyPem
          Fingerprint = fixture.Fingerprint }

    [<Test>]
    member _.``PEM validation accepts an actual leaf intermediate root chain``() =
        // Arrange
        let fixture = createValidCertificateFixture "api.example.test" [ "api.example.test" ]

        // Act
        let certificate = CertificateMaterial.normalizePem "api" fixture.ChainPem fixture.PrivateKeyPem None

        // Assert
        Assert.That(certificate.Name, Is.EqualTo("api"))
        Assert.That(certificate.Fingerprint, Is.EqualTo(fixture.Fingerprint))
        Assert.That(certificate.CertificatePem, Is.EqualTo(fixture.ChainPem))
        Assert.That(certificate.CertificatePem, Does.Contain(fixture.LeafCertificatePem.Trim()))
        Assert.That(certificate.CertificatePem, Does.Contain(fixture.IntermediateCertificatePem.Trim()))
        Assert.That(certificate.CertificatePem, Does.Contain(fixture.RootCertificatePem.Trim()))

    [<Test>]
    member _.``Certificate validation rejects mismatched private keys and fingerprints``() =
        // Arrange
        let fixture = createValidCertificateFixture "api.example.test" [ "api.example.test" ]
        let unrelated = createValidCertificateFixture "other.example.test" [ "other.example.test" ]
        let wrongKey = { normalized "api" fixture with PrivateKeyPem = unrelated.PrivateKeyPem }
        let wrongFingerprint = { normalized "api" fixture with Fingerprint = String.replicate 64 "0" }

        // Act
        let wrongKeyAction = TestDelegate(fun () -> TraefikCertificateValidation.validateNormalizedCertificates [ wrongKey ])
        let wrongFingerprintAction = TestDelegate(fun () -> TraefikCertificateValidation.validateNormalizedCertificates [ wrongFingerprint ])

        // Assert
        let keyError = Assert.Throws<InvalidOperationException>(wrongKeyAction)
        Assert.Throws<InvalidOperationException>(wrongFingerprintAction) |> ignore
        Assert.That(keyError.Message, Does.Not.Contain(unrelated.PrivateKeyPem))

    [<Test>]
    member _.``Certificate validation rejects expired future and client-auth-only certificates``() =
        // Arrange
        let now = DateTimeOffset.UtcNow
        let expired = createCertificateFixture "expired.example.test" [ "expired.example.test" ] (now.AddDays(-60.0)) (now.AddDays(-30.0)) [ "1.3.6.1.5.5.7.3.1" ]
        let future = createCertificateFixture "future.example.test" [ "future.example.test" ] (now.AddDays(30.0)) (now.AddDays(60.0)) [ "1.3.6.1.5.5.7.3.1" ]
        let clientAuth = createCertificateFixture "client.example.test" [ "client.example.test" ] (now.AddDays(-1.0)) (now.AddDays(30.0)) [ "1.3.6.1.5.5.7.3.2" ]

        // Act
        let expiredAction = TestDelegate(fun () -> TraefikCertificateValidation.validateNormalizedCertificates [ normalized "expired" expired ])
        let futureAction = TestDelegate(fun () -> TraefikCertificateValidation.validateNormalizedCertificates [ normalized "future" future ])
        let usageAction = TestDelegate(fun () -> TraefikCertificateValidation.validateNormalizedCertificates [ normalized "client" clientAuth ])

        // Assert
        Assert.Throws<InvalidOperationException>(expiredAction) |> ignore
        Assert.Throws<InvalidOperationException>(futureAction) |> ignore
        Assert.Throws<InvalidOperationException>(usageAction) |> ignore

    [<Test>]
    member _.``Certificate validation rejects malformed chains and overlapping certificate domains``() =
        // Arrange
        let api = createValidCertificateFixture "api.example.test" [ "api.example.test" ]
        let unrelated = createValidCertificateFixture "unrelated.example.test" [ "unrelated.example.test" ]
        let malformed = { normalized "api" api with CertificatePem = api.ChainPem + unrelated.LeafCertificatePem }
        let wildcard = createValidCertificateFixture "wildcard.example.test" [ "*.example.test" ]

        // Act
        let chainAction = TestDelegate(fun () -> TraefikCertificateValidation.validateNormalizedCertificates [ malformed ])
        let conflictAction = TestDelegate(fun () -> TraefikCertificateValidation.validateNormalizedCertificates [ normalized "api" api; normalized "wildcard" wildcard ])

        // Assert
        Assert.Throws<InvalidOperationException>(chainAction) |> ignore
        Assert.Throws<InvalidOperationException>(conflictAction) |> ignore

    [<Test>]
    member _.``Certificate SAN validation supports exact and single-label wildcard coverage``() =
        // Arrange
        let exact = createValidCertificateFixture "api.example.test" [ "api.example.test" ]
        let wildcard = createValidCertificateFixture "wildcard.example.test" [ "*.wildcard.example.test" ]
        let certificates = [ normalized "exact" exact; normalized "wildcard" wildcard ]
        let covered = [ "api", "api.example.test", "exact"; "web", "service.wildcard.example.test", "wildcard" ]
        let uncovered = [ "api", "other.example.test", "exact" ]
        let deepWildcard = [ "nested", "deep.service.wildcard.example.test", "wildcard" ]

        // Act
        TraefikCertificateValidation.validateRouterCertificateCoverage covered certificates
        let uncoveredHostAction = TestDelegate(fun () -> TraefikCertificateValidation.validateRouterCertificateCoverage uncovered certificates)
        let deepWildcardAction = TestDelegate(fun () -> TraefikCertificateValidation.validateRouterCertificateCoverage deepWildcard certificates)

        // Assert
        Assert.Throws<InvalidOperationException>(uncoveredHostAction) |> ignore
        Assert.Throws<InvalidOperationException>(deepWildcardAction) |> ignore

    [<Test>]
    member _.``Certificate source constructors defer file reads and stream creation``() =
        // Arrange
        use temporary = new TemporaryDirectory("keroosha-certificate-lazy-")
        let path = Path.Combine(temporary.Path, "certificate.pem")
        let mutable streamCalls = 0
        let streamContent =
            Content.stream(fun (_: CancellationToken) ->
                streamCalls <- streamCalls + 1
                Task.FromResult<Stream>(new MemoryStream([| 1uy; 2uy; 3uy |])))
        let fileContent = Content.file path
        let _specification =
            traefik {
                entryPoint "web" { listen 8080 }
                pemCertificate "deferred" {
                    chain fileContent
                    privateKey streamContent
                }
            }

        // Act
        let fileWasReadDuringConstruction = File.Exists(path)
        let streamWasOpenedDuringConstruction = streamCalls <> 0

        // Assert
        Assert.That(fileWasReadDuringConstruction, Is.False)
        Assert.That(streamWasOpenedDuringConstruction, Is.False)

    [<Test>]
    member _.``PEM normalization decrypts the key and preserves leaf intermediate root order``() =
        // Arrange
        let fixture = createValidCertificateFixture "encrypted.example.test" [ "encrypted.example.test" ]
        let unorderedChain = String.concat "\n" [ fixture.RootCertificatePem; fixture.LeafCertificatePem; fixture.IntermediateCertificatePem ] + "\n"

        // Act
        let certificate =
            CertificateMaterial.normalizePem
                "encrypted"
                unorderedChain
                fixture.EncryptedPrivateKeyPem
                (Some fixture.PfxPassword)

        // Assert
        Assert.That(certificate.Name, Is.EqualTo("encrypted"))
        Assert.That(certificate.Fingerprint, Is.EqualTo(fixture.Fingerprint))
        Assert.That(certificate.CertificatePem, Is.EqualTo(fixture.ChainPem))
        Assert.That(certificate.CertificatePem.Split([| "-----BEGIN CERTIFICATE-----" |], StringSplitOptions.None).Length, Is.EqualTo(4))
        Assert.That(certificate.PrivateKeyPem, Does.StartWith("-----BEGIN PRIVATE KEY-----"))

    [<Test>]
    member _.``PEM normalization rejects missing or wrong encryption passwords without disclosure``() =
        // Arrange
        let fixture = createValidCertificateFixture "encrypted.example.test" [ "encrypted.example.test" ]
        let missingPassword = fun () -> CertificateMaterial.normalizePem "encrypted" fixture.ChainPem fixture.EncryptedPrivateKeyPem None
        let wrongPassword = fun () -> CertificateMaterial.normalizePem "encrypted" fixture.ChainPem fixture.EncryptedPrivateKeyPem (Some "not-the-password")
        // Act
        let missingPasswordAction = TestDelegate(fun () -> missingPassword () |> ignore)
        let wrongPasswordAction = TestDelegate(fun () -> wrongPassword () |> ignore)

        // Assert
        Assert.Throws<InvalidOperationException>(missingPasswordAction) |> ignore
        let wrongError = Assert.Throws<InvalidOperationException>(wrongPasswordAction)
        Assert.That(wrongError.Message, Does.Not.Contain("not-the-password"))
        Assert.That(wrongError.Message, Does.Not.Contain(fixture.EncryptedPrivateKeyPem))

    [<Test>]
    member _.``PKCS12 normalization accepts one matching private key``() =
        // Arrange
        let fixture = createValidCertificateFixture "pfx.example.test" [ "pfx.example.test" ]

        // Act
        let certificate = CertificateMaterial.normalizePkcs12 "pfx" fixture.PfxBytes (Some fixture.PfxPassword)

        // Assert
        Assert.That(certificate.Fingerprint, Is.EqualTo(fixture.Fingerprint))
        Assert.That(certificate.CertificatePem.Split([| "-----BEGIN CERTIFICATE-----" |], StringSplitOptions.None).Length, Is.EqualTo(4))
        Assert.That(certificate.PrivateKeyPem, Does.StartWith("-----BEGIN PRIVATE KEY-----"))

    [<Test>]
    member _.``PKCS12 normalization rejects missing wrong and ambiguous key material``() =
        // Arrange
        let fixture = createValidCertificateFixture "pfx.example.test" [ "pfx.example.test" ]
        let multiKey = createMultiKeyPfx "multi-key-test-password"
        let missingPassword = fun () -> CertificateMaterial.normalizePkcs12 "pfx" fixture.PfxBytes None
        let wrongPassword = fun () -> CertificateMaterial.normalizePkcs12 "pfx" fixture.PfxBytes (Some "not-the-password")
        let ambiguousKeys = fun () -> CertificateMaterial.normalizePkcs12 "pfx" multiKey (Some "multi-key-test-password")

        // Act
        let missingPasswordAction = TestDelegate(fun () -> missingPassword () |> ignore)
        let wrongPasswordAction = TestDelegate(fun () -> wrongPassword () |> ignore)
        let ambiguousKeysAction = TestDelegate(fun () -> ambiguousKeys () |> ignore)

        // Assert
        Assert.Throws<InvalidOperationException>(missingPasswordAction) |> ignore
        let wrongError = Assert.Throws<InvalidOperationException>(wrongPasswordAction)
        let ambiguousError = Assert.Throws<InvalidOperationException>(ambiguousKeysAction)
        Assert.That(wrongError.Message, Does.Not.Contain("not-the-password"))
        Assert.That(ambiguousError.Message, Does.Not.Contain("multi-key-test-password"))

    [<Test>]
    member _.``PEM normalization rejects expired future client-auth mismatched-key and malformed-chain inputs``() =
        // Arrange
        let now = DateTimeOffset.UtcNow
        let expired = createCertificateFixture "expired.example.test" [ "expired.example.test" ] (now.AddDays(-60.0)) (now.AddDays(-30.0)) [ "1.3.6.1.5.5.7.3.1" ]
        let future = createCertificateFixture "future.example.test" [ "future.example.test" ] (now.AddDays(30.0)) (now.AddDays(60.0)) [ "1.3.6.1.5.5.7.3.1" ]
        let clientAuth = createCertificateFixture "client.example.test" [ "client.example.test" ] (now.AddDays(-1.0)) (now.AddDays(30.0)) [ "1.3.6.1.5.5.7.3.2" ]
        let valid = createValidCertificateFixture "valid.example.test" [ "valid.example.test" ]
        let unrelated = createValidCertificateFixture "unrelated.example.test" [ "unrelated.example.test" ]
        let expiredInput = fun () -> CertificateMaterial.normalizePem "expired" expired.ChainPem expired.PrivateKeyPem None
        let futureInput = fun () -> CertificateMaterial.normalizePem "future" future.ChainPem future.PrivateKeyPem None
        let clientAuthInput = fun () -> CertificateMaterial.normalizePem "client" clientAuth.ChainPem clientAuth.PrivateKeyPem None
        let mismatchedKey = fun () -> CertificateMaterial.normalizePem "valid" valid.ChainPem unrelated.PrivateKeyPem None
        let malformedChain = fun () -> CertificateMaterial.normalizePem "valid" (valid.ChainPem + unrelated.LeafCertificatePem) valid.PrivateKeyPem None

        // Act
        let actions =
            [ expiredInput; futureInput; clientAuthInput; mismatchedKey; malformedChain ]
            |> List.map (fun attempt -> TestDelegate(fun () -> attempt () |> ignore))

        // Assert
        for action in actions do Assert.Throws<InvalidOperationException>(action) |> ignore
