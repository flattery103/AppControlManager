using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AppGuard.Core;

internal static class CrossSignedCertificateBehavior
{
    public static void Run()
    {
        using var trustedKey = RSA.Create(2048);
        using var issuerKey = RSA.Create(2048);
        using var sameSubjectKey = RSA.Create(2048);
        using var timestampKey = RSA.Create(2048);

        var now = DateTimeOffset.UtcNow;
        var trustedRequest = Request("CN=Trusted Root", trustedKey);
        using var trustedSelfSigned = trustedRequest.CreateSelfSigned(now.AddDays(-1), now.AddYears(2));
        var issuerRequest = Request("CN=Alternate Issuer", issuerKey);
        using var alternateIssuer = issuerRequest.CreateSelfSigned(now.AddDays(-1), now.AddYears(2));
        using var trustedCrossSigned = trustedRequest.Create(
            alternateIssuer,
            now.AddDays(-1),
            now.AddYears(1),
            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        var sameSubjectRequest = Request("CN=Trusted Root", sameSubjectKey);
        using var sameSubject = sameSubjectRequest.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
        var timestampRequest = Request("CN=Timestamp Certificate", timestampKey);
        using var timestamp = timestampRequest.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));

        var hashes = AuthenticodeCertificateIdentity.CollectEquivalentSignerTbsHashes(
            new[] { trustedSelfSigned },
            new[] { trustedCrossSigned, sameSubject, timestamp });
        var crossSignedHashes = AuthenticodeCertificateIdentity.ComputeTbsHashes(trustedCrossSigned);
        var sameSubjectHashes = AuthenticodeCertificateIdentity.ComputeTbsHashes(sameSubject);
        var timestampHashes = AuthenticodeCertificateIdentity.ComputeTbsHashes(timestamp);

        Require(crossSignedHashes.All(hashes.Contains), "A cross-signed certificate with a verified public key must be accepted.");
        Require(sameSubjectHashes.All(x => !hashes.Contains(x)), "A same-subject certificate with a different public key must be rejected.");
        Require(timestampHashes.All(x => !hashes.Contains(x)), "An unrelated embedded timestamp certificate must be rejected.");

        var malformed = Path.Combine(Path.GetTempPath(), $"acm-malformed-{Guid.NewGuid():N}.exe");
        try
        {
            File.WriteAllBytes(malformed, new byte[] { 0x4D, 0x5A });
            RequireThrows<InvalidDataException>(
                () => AuthenticodeCertificateIdentity.ReadEmbeddedCertificates(malformed),
                "A malformed PE certificate table must fail closed.");
        }
        finally
        {
            if (File.Exists(malformed)) File.Delete(malformed);
        }
    }

    private static CertificateRequest Request(string subject, RSA key)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request;
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static void RequireThrows<TException>(Action action, string message) where TException : Exception
    {
        try { action(); }
        catch (TException) { return; }
        throw new InvalidOperationException(message);
    }
}
