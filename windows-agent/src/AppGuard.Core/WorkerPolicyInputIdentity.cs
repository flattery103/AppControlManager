using System.ComponentModel;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace AppGuard.Core;

public sealed class WorkerPolicyInputIdentity
{
    public string FileName { get; }
    public string? OriginalFileName { get; }
    public string? InternalName { get; }
    public string? ProductName { get; }
    public string? FileVersion { get; }
    public string ContentSha256 { get; }
    public string? Publisher { get; }
    public IReadOnlySet<string> ExpectedPolicyHashes { get; }
    public IReadOnlySet<string> PublisherNames { get; }
    public IReadOnlySet<string> SignerTbsHashes { get; }

    public WorkerPolicyInputIdentity(
        string fileName,
        string? originalFileName,
        string? internalName,
        string? productName,
        string? fileVersion,
        string contentSha256,
        IEnumerable<string> expectedPolicyHashes,
        IEnumerable<string> publisherNames,
        IEnumerable<string> signerTbsHashes)
    {
        FileName = Required(fileName, nameof(fileName));
        OriginalFileName = Clean(originalFileName);
        InternalName = Clean(internalName);
        ProductName = Clean(productName);
        FileVersion = NormalizeVersion(fileVersion);
        ContentSha256 = RequiredHex(contentSha256, 64, nameof(contentSha256));
        ExpectedPolicyHashes = HexSet(expectedPolicyHashes, nameof(expectedPolicyHashes));
        PublisherNames = TextSet(publisherNames);
        SignerTbsHashes = HexSet(signerTbsHashes, nameof(signerTbsHashes));
        Publisher = PublisherNames.FirstOrDefault();
        if (!ExpectedPolicyHashes.Any(x => x.Length == 40) || !ExpectedPolicyHashes.Any(x => x.Length == 64))
            throw new ArgumentException("Expected policy hashes must contain SHA-1 and SHA-256 identities.", nameof(expectedPolicyHashes));
    }

    public static WorkerPolicyInputIdentity FromFile(string path)
    {
        var canonical = Path.GetFullPath(path);
        if (!File.Exists(canonical)) throw new FileNotFoundException("Staged worker input is missing.", canonical);

        string flatSha1;
        string flatSha256;
        using (var stream = new FileStream(canonical, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            flatSha256 = Convert.ToHexString(SHA256.HashData(stream));
            stream.Position = 0;
            flatSha1 = Convert.ToHexString(SHA1.HashData(stream));
        }
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { flatSha1, flatSha256 };
        hashes.Add(CalculateAuthenticodeHash(canonical, "SHA1"));
        hashes.Add(CalculateAuthenticodeHash(canonical, "SHA256"));

        var version = FileVersionInfo.GetVersionInfo(canonical);
        var numericVersion = version.FileVersion is null
            ? null
            : $"{Math.Max(0, version.FileMajorPart)}.{Math.Max(0, version.FileMinorPart)}.{Math.Max(0, version.FileBuildPart)}.{Math.Max(0, version.FilePrivatePart)}";
        var publishers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var signerTbsHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var signer = new X509Certificate2(X509Certificate.CreateFromSignedFile(canonical));
            AddPublisherNames(signer, publishers);
            AddTbsHashes(signer, signerTbsHashes);
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            _ = chain.Build(signer);
            foreach (var element in chain.ChainElements)
                AddTbsHashes(element.Certificate, signerTbsHashes);
        }
        catch (CryptographicException) { }

        return new WorkerPolicyInputIdentity(
            Path.GetFileName(canonical),
            version.OriginalFilename,
            version.InternalName,
            version.ProductName,
            numericVersion,
            flatSha256,
            hashes,
            publishers,
            signerTbsHashes);
    }

    public bool MatchesFileName(string? value)
    {
        var candidate = Clean(value);
        if (candidate is null) return false;
        return new[] { FileName, OriginalFileName, InternalName }
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Any(x => candidate.Equals(x, StringComparison.OrdinalIgnoreCase));
    }

    public bool MatchesVersion(string? value)
        => FileVersion is not null && string.Equals(FileVersion, NormalizeVersion(value), StringComparison.OrdinalIgnoreCase);

    private static string CalculateAuthenticodeHash(string path, string algorithm)
    {
        if (!CryptCATAdminAcquireContext2(out var catalogAdmin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not initialize {algorithm} App Control hashing.");
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            uint byteCount = 0;
            if (!CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, handle, ref byteCount, null, 0) || byteCount == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not size the {algorithm} App Control hash.");
            var bytes = new byte[byteCount];
            if (!CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, handle, ref byteCount, bytes, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not calculate the {algorithm} App Control hash.");
            return Convert.ToHexString(bytes.AsSpan(0, checked((int)byteCount)));
        }
        finally { _ = CryptCATAdminReleaseContext(catalogAdmin, 0); }
    }

    private static void AddPublisherNames(X509Certificate2 certificate, ISet<string> publishers)
    {
        foreach (var value in new[] { certificate.Subject, certificate.GetNameInfo(X509NameType.SimpleName, false) })
        {
            var clean = Clean(value);
            if (clean is not null) publishers.Add(clean);
        }
    }

    private static void AddTbsHashes(X509Certificate2 certificate, ISet<string> hashes)
    {
        var certificateReader = new AsnReader(certificate.RawData, AsnEncodingRules.DER);
        var certificateSequence = certificateReader.ReadSequence();
        var tbsCertificate = certificateSequence.ReadEncodedValue().Span;
        hashes.Add(Convert.ToHexString(SHA1.HashData(tbsCertificate)));
        hashes.Add(Convert.ToHexString(SHA256.HashData(tbsCertificate)));
    }

    private static string Required(string value, string parameterName)
        => Clean(value) ?? throw new ArgumentException("Value is required.", parameterName);

    private static string RequiredHex(string value, int length, string parameterName)
    {
        var clean = Required(value, parameterName).ToUpperInvariant();
        if (clean.Length != length || clean.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("Value is not a valid hexadecimal digest.", parameterName);
        return clean;
    }

    private static IReadOnlySet<string> HexSet(IEnumerable<string> values, string parameterName)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var value in values ?? throw new ArgumentNullException(parameterName))
        {
            var clean = Required(value, parameterName).ToUpperInvariant();
            if (clean.Length is not (40 or 64) || clean.Any(c => !Uri.IsHexDigit(c)))
                throw new ArgumentException("Digest set contains an invalid SHA-1/SHA-256 value.", parameterName);
            set.Add(clean);
        }
        return set;
    }

    private static IReadOnlySet<string> TextSet(IEnumerable<string> values)
        => new HashSet<string>(
            (values ?? Array.Empty<string>()).Select(Clean).Where(x => x is not null).Select(x => x!),
            StringComparer.OrdinalIgnoreCase);

    private static string? NormalizeVersion(string? value)
    {
        var clean = Clean(value);
        return clean is not null && Version.TryParse(clean, out var version) ? version.ToString(4) : null;
    }

    private static string? Clean(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr catalogAdmin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catalogAdmin, SafeFileHandle file, ref uint hashByteCount, [Out] byte[]? hash, uint flags);

    [DllImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr catalogAdmin, uint flags);
}
