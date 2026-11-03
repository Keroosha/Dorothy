namespace Dorothy.DSL

open System
open System.Globalization
open System.Collections.Generic
open System.IO
open System.Net
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates
open System.Threading
open System.Threading.Tasks
open Pulumi

/// A string supplied literally or through a Pulumi Output, retaining its dependency and secrecy metadata.
type TraefikStringInput =
    | LiteralString of string
    | OutputString of Output<string>

/// The encoding and deferred origin of certificate material.
type internal CertificateContentKind =
    | PemText of TraefikStringInput
    | Base64Text of TraefikStringInput
    | FilePath of string
    | StreamFactory of (CancellationToken -> Task<Stream>)

/// Deferred certificate bytes. Creating a value performs no file or stream IO.
[<Sealed>]
type CertificateContent internal (kind: CertificateContentKind) =
    member internal _.Kind = kind

/// Constructors for certificate material; file and stream contents are read only during resolution.
[<AbstractClass; Sealed>]
type Content private () =
    /// Supplies inline PEM text.
    static member pem(value: string) = CertificateContent(PemText(LiteralString value))

    /// Supplies inline PEM text from a Pulumi output.
    static member pem(value: Output<string>) = CertificateContent(PemText(OutputString value))

    /// Supplies base64-encoded certificate or PKCS#12 bytes.
    static member base64(value: string) = CertificateContent(Base64Text(LiteralString value))

    /// Supplies base64-encoded certificate or PKCS#12 bytes from a Pulumi output.
    static member base64(value: Output<string>) = CertificateContent(Base64Text(OutputString value))

    /// Supplies a path read during deployment resolution, not while the DSL is constructed.
    static member file(path: string) = CertificateContent(FilePath path)

    /// Supplies a stream factory invoked once during resolution; the returned stream is disposed.
    static member stream(factory: CancellationToken -> Task<Stream>) =
        CertificateContent(StreamFactory factory)

/// Certificate/key material normalized for the native Traefik resource.
type NormalizedCertificate =
    { Name: string
      CertificatePem: string
      PrivateKeyPem: string
      Fingerprint: string }

module internal CertificateMaterial =
    let private genericFailure () =
        raise (InvalidOperationException("Certificate validation failed."))

    let private fixedTimeEqual (left: byte array) (right: byte array) =
        left.Length = right.Length && CryptographicOperations.FixedTimeEquals(left, right)

    let private isCurrent (certificate: X509Certificate2) =
        let now = DateTime.UtcNow
        certificate.NotBefore.ToUniversalTime() <= now && now <= certificate.NotAfter.ToUniversalTime()

    let private toArray (certificates: X509Certificate2Collection) =
        certificates |> Seq.cast<X509Certificate2> |> Seq.toArray

    let private certificatePem (certificate: X509Certificate2) = certificate.ExportCertificatePem()

    let private distinctCertificates (certificates: X509Certificate2 array) =
        let seen = HashSet<string>(StringComparer.Ordinal)
        certificates
        |> Array.filter (fun certificate -> seen.Add(Convert.ToBase64String(certificate.RawData)))

    let private sameName (left: X500DistinguishedName) (right: X500DistinguishedName) =
        fixedTimeEqual left.RawData right.RawData

    let private orderChain (certificates: X509Certificate2 array) =
        if certificates.Length = 0 then genericFailure ()

        let certificates = distinctCertificates certificates
        let leafCandidates =
            certificates
            |> Array.mapi (fun index certificate -> index, certificate)
            |> Array.filter (fun (index, candidate) ->
                certificates
                |> Array.mapi (fun childIndex child -> childIndex, child)
                |> Array.exists (fun (childIndex, child) ->
                    childIndex <> index && sameName child.IssuerName candidate.SubjectName)
                |> not)

        if leafCandidates.Length <> 1 then genericFailure ()

        let leafIndex, leaf = leafCandidates[0]
        let used = HashSet<int>()
        used.Add(leafIndex) |> ignore
        let ordered = ResizeArray<X509Certificate2>()
        ordered.Add(leaf)
        let mutable current = leaf
        let mutable complete = false

        while not complete do
            let issuers =
                certificates
                |> Array.mapi (fun index candidate -> index, candidate)
                |> Array.filter (fun (index, candidate) ->
                    not (used.Contains index)
                    && sameName current.IssuerName candidate.SubjectName)

            if issuers.Length > 1 then genericFailure ()
            elif issuers.Length = 0 then
                complete <- true
            else
                let index, issuer = issuers[0]
                used.Add(index) |> ignore
                ordered.Add(issuer)
                current <- issuer

        if used.Count <> certificates.Length then genericFailure ()
        ordered.ToArray()

    let private verifyChain (ordered: X509Certificate2 array) =
        use chain = new X509Chain()
        chain.ChainPolicy.RevocationMode <- X509RevocationMode.NoCheck
        chain.ChainPolicy.VerificationFlags <- X509VerificationFlags.AllowUnknownCertificateAuthority
        chain.ChainPolicy.DisableCertificateDownloads <- true
        chain.ChainPolicy.ApplicationPolicy.Add(Oid("1.3.6.1.5.5.7.3.1")) |> ignore

        for index in 1 .. ordered.Length - 1 do
            chain.ChainPolicy.ExtraStore.Add(ordered[index]) |> ignore

        let built = chain.Build(ordered[0])
        if chain.ChainElements.Count < ordered.Length then genericFailure ()
        for index in 0 .. ordered.Length - 1 do
            if not (fixedTimeEqual chain.ChainElements[index].Certificate.RawData ordered[index].RawData) then
                genericFailure ()

        let allowedStatusMask =
            int (X509ChainStatusFlags.UntrustedRoot ||| X509ChainStatusFlags.PartialChain)
        let invalidStatus =
            chain.ChainStatus
            |> Array.exists (fun status -> (int status.Status &&& (~~~allowedStatusMask)) <> 0)

        if invalidStatus || (not built && chain.ChainStatus.Length = 0) then genericFailure ()

    let private normalizePrivateKey (certificate: X509Certificate2) =
        match certificate.GetRSAPrivateKey() with
        | rsa when not (isNull rsa) ->
            use rsa = rsa
            rsa.ExportPkcs8PrivateKeyPem()
        | _ ->
            match certificate.GetECDsaPrivateKey() with
            | ecdsa when not (isNull ecdsa) ->
                use ecdsa = ecdsa
                ecdsa.ExportPkcs8PrivateKeyPem()
            | _ -> genericFailure ()

    let private sanExtension (certificate: X509Certificate2) =
        let extensions =
            certificate.Extensions
            |> Seq.cast<X509Extension>
            |> Seq.filter (fun extension ->
                not (isNull extension.Oid)
                && String.Equals(extension.Oid.Value, "2.5.29.17", StringComparison.Ordinal))
            |> Seq.toArray

        if extensions.Length <> 1 then genericFailure ()
        let extension = extensions[0]
        X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical)

    let private canonicalDnsName (value: string) =
        if String.IsNullOrWhiteSpace value then genericFailure ()
        let trimmed = value.TrimEnd('.').ToLowerInvariant()
        let wildcard = trimmed.StartsWith("*.", StringComparison.Ordinal)
        let name = if wildcard then trimmed.Substring(2) else trimmed

        if name.Contains('*') then genericFailure ()
        let ascii = IdnMapping().GetAscii(name).ToLowerInvariant()
        if Uri.CheckHostName(ascii) <> UriHostNameType.Dns then genericFailure ()
        if wildcard then "*." + ascii else ascii

    let private sanNames (certificate: X509Certificate2) =
        let extension = sanExtension certificate
        let dns = extension.EnumerateDnsNames() |> Seq.map canonicalDnsName |> Seq.distinct |> Seq.toList
        let ips = extension.EnumerateIPAddresses() |> Seq.map (fun address -> address.ToString().ToLowerInvariant()) |> Seq.distinct |> Seq.toList
        dns, ips

    let private fingerprint (certificate: X509Certificate2) =
        SHA256.HashData(certificate.RawData) |> Convert.ToHexString |> fun value -> value.ToLowerInvariant()

    let private attachPemKey (certificate: X509Certificate2) (privateKeyPem: string) (password: string option) =
        let encrypted = privateKeyPem.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal)

        if encrypted && password.IsNone then genericFailure ()

        let certificateText = certificatePem certificate
        if encrypted then
            X509Certificate2.CreateFromEncryptedPem(certificateText.AsSpan(), privateKeyPem.AsSpan(), (defaultArg password "").AsSpan())
        else
            X509Certificate2.CreateFromPem(certificateText.AsSpan(), privateKeyPem.AsSpan())

    let private normalized (name: string) (certificates: X509Certificate2 array) (leafWithKey: X509Certificate2) =
        let ordered = orderChain certificates
        if not (ordered |> Array.forall isCurrent) then genericFailure ()
        verifyChain ordered

        let leaf = ordered[0]
        if not (fixedTimeEqual leaf.RawData leafWithKey.RawData) || not leafWithKey.HasPrivateKey then
            genericFailure ()

        let normalizedChain =
            ordered
            |> Array.map (fun certificate -> (certificatePem certificate).TrimEnd([| '\r'; '\n' |]))
            |> String.concat "\n"
            |> fun chain -> chain + "\n"
        { Name = name
          CertificatePem = normalizedChain
          PrivateKeyPem = normalizePrivateKey leafWithKey
          Fingerprint = fingerprint leaf }

    let normalizePem (name: string) (certificatePemText: string) (privateKeyPem: string) (password: string option) =
        try
            if isNull certificatePemText || isNull privateKeyPem then genericFailure ()

            let collection = X509Certificate2Collection()
            collection.ImportFromPem(certificatePemText.AsSpan())
            let certificates = toArray collection
            try
                let ordered = orderChain certificates
                use leafWithKey = attachPemKey ordered[0] privateKeyPem password
                normalized name certificates leafWithKey
            finally
                for certificate in certificates do certificate.Dispose()
        with
        | :? OperationCanceledException -> reraise ()
        | _ -> genericFailure ()

    let normalizePkcs12 (name: string) (pfxBytes: byte array) (password: string option) =
        try
            if isNull pfxBytes then genericFailure ()
            let limits = Pkcs12LoaderLimits()
            limits.MaxKeys <- Nullable<int>(1)
            let imported =
                X509CertificateLoader.LoadPkcs12Collection(
                    pfxBytes,
                    defaultArg password null,
                    X509KeyStorageFlags.EphemeralKeySet,
                    limits
                )
            let certificates = toArray imported
            try
                let privateKeys = certificates |> Array.filter (fun certificate -> certificate.HasPrivateKey)
                if privateKeys.Length <> 1 then genericFailure ()
                let ordered = orderChain certificates
                let leafWithKey = privateKeys[0]
                if not (fixedTimeEqual ordered[0].RawData leafWithKey.RawData) then genericFailure ()
                normalized name certificates leafWithKey
            finally
                for certificate in certificates do certificate.Dispose()
        with
        | :? OperationCanceledException -> reraise ()
        | _ -> genericFailure ()

    let private wildcardMatches (pattern: string) (host: string) =
        if pattern.StartsWith("*.", StringComparison.Ordinal) then
            let suffix = pattern.Substring(2)
            host.EndsWith("." + suffix, StringComparison.Ordinal)
            && not (host.Substring(0, host.Length - suffix.Length - 1).Contains('.'))
        else
            String.Equals(pattern, host, StringComparison.Ordinal)

    let private domainsOverlap (left: string) (right: string) =
        if String.Equals(left, right, StringComparison.Ordinal) then true
        elif left.StartsWith("*.", StringComparison.Ordinal) then wildcardMatches left right
        elif right.StartsWith("*.", StringComparison.Ordinal) then wildcardMatches right left
        else false

    let private metadata (certificate: NormalizedCertificate) =
        if String.IsNullOrWhiteSpace certificate.Name
           || isNull certificate.CertificatePem
           || isNull certificate.PrivateKeyPem
           || isNull certificate.Fingerprint then
            genericFailure ()

        let collection = X509Certificate2Collection()
        collection.ImportFromPem(certificate.CertificatePem.AsSpan())
        let certificates = toArray collection
        try
            let ordered = orderChain certificates
            use leafWithKey = attachPemKey ordered[0] certificate.PrivateKeyPem None
            let parsed = normalized certificate.Name certificates leafWithKey
            if not (String.Equals(parsed.Fingerprint, certificate.Fingerprint, StringComparison.Ordinal)) then
                genericFailure ()
            let dns, ips = sanNames ordered[0]
            parsed, dns, ips
        finally
            for item in certificates do item.Dispose()

    let validateNormalizedCertificates (certificates: seq<NormalizedCertificate>) =
        try
            let values = certificates |> Seq.toArray
            let names = HashSet<string>(StringComparer.Ordinal)
            let domains = ResizeArray<string * string>()

            for certificate in values do
                if not (names.Add certificate.Name) then genericFailure ()
                let _, dnsNames, ipAddresses = metadata certificate
                for domain in dnsNames do domains.Add(certificate.Name, domain)
                for address in ipAddresses do domains.Add(certificate.Name, "ip:" + address)

            for leftIndex in 0 .. domains.Count - 1 do
                for rightIndex in leftIndex + 1 .. domains.Count - 1 do
                    let leftName, leftDomain = domains[leftIndex]
                    let rightName, rightDomain = domains[rightIndex]
                    if leftName <> rightName && domainsOverlap leftDomain rightDomain then genericFailure ()
        with
        | :? OperationCanceledException -> reraise ()
        | _ -> genericFailure ()

    let validateCertificateCoverage (routers: seq<string * string * string>) (certificates: seq<NormalizedCertificate>) =
        try
            let certificateArray = certificates |> Seq.toArray
            let byName = certificateArray |> Seq.map (fun certificate -> certificate.Name, certificate) |> Map.ofSeq

            for _, host, certificateName in routers do
                match Map.tryFind certificateName byName with
                | None -> genericFailure ()
                | Some certificate ->
                    let _, dnsNames, ipAddresses = metadata certificate
                    let requestedIp =
                        match IPAddress.TryParse(host) with
                        | true, address -> Some(address.ToString().ToLowerInvariant())
                        | _ -> None

                    match requestedIp with
                    | Some address when ipAddresses |> List.contains address -> ()
                    | Some _ -> genericFailure ()
                    | None ->
                        let requested = canonicalDnsName host
                        if requested.StartsWith("*.", StringComparison.Ordinal)
                           || not (dnsNames |> List.exists (fun domain -> wildcardMatches domain requested)) then
                            genericFailure ()
        with
        | :? OperationCanceledException -> reraise ()
        | _ -> genericFailure ()

/// Safe, local validation shared by DSL resolution and direct native-resource inputs.
[<RequireQualifiedAccess>]
module TraefikCertificateValidation =
    /// Validates certificate/key correspondence, fingerprint, validity, chain coherence, and conflicting SAN coverage.
    let validateNormalizedCertificates (certificates: seq<NormalizedCertificate>) =
        CertificateMaterial.validateNormalizedCertificates certificates
    /// Validates provided router hostnames against their named certificate SANs.
    let validateRouterCertificateCoverage (routers: seq<string * string * string>) (certificates: seq<NormalizedCertificate>) =
        CertificateMaterial.validateCertificateCoverage routers certificates
