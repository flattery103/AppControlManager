using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AppGuard.Core;

public static class AuthenticodeCertificateIdentity
{
    public const int MaximumCertificateTableBytes = 8 * 1024 * 1024;
    public const int MaximumCertificateEntries = 16;
    public const int MaximumEmbeddedCertificates = 256;

    public static IReadOnlySet<string> CollectEquivalentSignerTbsHashes(
        IEnumerable<X509Certificate2> verifiedChain,
        IEnumerable<X509Certificate2> embeddedCertificates)
    {
        var verified = verifiedChain?.ToArray() ?? throw new ArgumentNullException(nameof(verifiedChain));
        var embedded = embeddedCertificates?.ToArray() ?? throw new ArgumentNullException(nameof(embeddedCertificates));
        var verifiedPublicKeys = new HashSet<string>(verified.Select(PublicKeyFingerprint), StringComparer.OrdinalIgnoreCase);
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var certificate in verified)
            hashes.UnionWith(ComputeTbsHashes(certificate));

        foreach (var certificate in embedded)
        {
            if (verifiedPublicKeys.Contains(PublicKeyFingerprint(certificate)))
                hashes.UnionWith(ComputeTbsHashes(certificate));
        }

        return hashes;
    }

    public static IReadOnlySet<string> ComputeTbsHashes(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var certificateReader = new AsnReader(certificate.RawData, AsnEncodingRules.DER);
        var certificateSequence = certificateReader.ReadSequence();
        var tbsCertificate = certificateSequence.ReadEncodedValue().Span;
        return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Convert.ToHexString(SHA1.HashData(tbsCertificate)),
            Convert.ToHexString(SHA256.HashData(tbsCertificate)),
            Convert.ToHexString(SHA384.HashData(tbsCertificate))
        };
    }

    public static string PublicKeyFingerprint(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(certificate.PublicKey.Oid.Value ?? string.Empty));
        hash.AppendData(new byte[] { 0 });
        hash.AppendData(certificate.PublicKey.EncodedParameters.RawData);
        hash.AppendData(new byte[] { 0 });
        hash.AppendData(certificate.PublicKey.EncodedKeyValue.RawData);
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    public static IReadOnlyList<X509Certificate2> ReadEmbeddedCertificates(string path)
    {
        var canonical = Path.GetFullPath(path);
        using var stream = new FileStream(canonical, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);

        RequireRange(stream, 0, 64, "DOS header");
        if (reader.ReadUInt16() != 0x5A4D) throw new InvalidDataException("Signed input does not contain an MZ header.");
        stream.Position = 0x3C;
        var peOffset = reader.ReadInt32();
        RequireRange(stream, peOffset, 24, "PE header");
        stream.Position = peOffset;
        if (reader.ReadUInt32() != 0x00004550) throw new InvalidDataException("Signed input does not contain a PE header.");
        stream.Position = peOffset + 20;
        var optionalHeaderSize = reader.ReadUInt16();
        var optionalHeaderOffset = checked(peOffset + 24);
        RequireRange(stream, optionalHeaderOffset, optionalHeaderSize, "optional header");
        stream.Position = optionalHeaderOffset;
        var magic = reader.ReadUInt16();
        var dataDirectoryOffset = magic switch
        {
            0x10B => checked(optionalHeaderOffset + 96),
            0x20B => checked(optionalHeaderOffset + 112),
            _ => throw new InvalidDataException($"Unsupported PE optional-header magic: 0x{magic:X}.")
        };
        var numberOfDirectoriesOffset = magic == 0x10B ? optionalHeaderOffset + 92 : optionalHeaderOffset + 108;
        RequireRange(stream, numberOfDirectoriesOffset, 4, "data-directory count");
        stream.Position = numberOfDirectoriesOffset;
        if (reader.ReadUInt32() < 5) throw new InvalidDataException("PE input does not contain a certificate directory.");

        var securityDirectoryOffset = checked(dataDirectoryOffset + (4 * 8));
        if (securityDirectoryOffset + 8L > optionalHeaderOffset + optionalHeaderSize)
            throw new InvalidDataException("PE optional header does not contain a complete certificate directory.");
        RequireRange(stream, securityDirectoryOffset, 8, "certificate directory");
        stream.Position = securityDirectoryOffset;
        var certificateOffset = reader.ReadUInt32();
        var certificateSize = reader.ReadUInt32();
        if (certificateOffset == 0 || certificateSize == 0)
            throw new InvalidDataException("PE input does not contain an Authenticode certificate table.");
        if (certificateSize > MaximumCertificateTableBytes)
            throw new InvalidDataException("Authenticode certificate table exceeds the safety limit.");
        RequireRange(stream, certificateOffset, certificateSize, "certificate table");

        var certificates = new List<X509Certificate2>();
        try
        {
            long cursor = certificateOffset;
            var end = checked(cursor + certificateSize);
            var entryCount = 0;
            while (cursor < end)
            {
                if (++entryCount > MaximumCertificateEntries)
                    throw new InvalidDataException("Authenticode certificate entry count exceeds the safety limit.");
                RequireRange(stream, cursor, 8, "WIN_CERTIFICATE header");
                stream.Position = cursor;
                var length = reader.ReadUInt32();
                var revision = reader.ReadUInt16();
                var certificateType = reader.ReadUInt16();
                if (length < 8 || checked(cursor + length) > end)
                    throw new InvalidDataException("Authenticode certificate entry has an invalid length.");
                if (revision != 0x0200 || certificateType != 0x0002)
                    throw new InvalidDataException("Authenticode certificate entry uses an unsupported format.");

                var payloadLength = checked((int)length - 8);
                var payload = reader.ReadBytes(payloadLength);
                if (payload.Length != payloadLength)
                    throw new InvalidDataException("Authenticode certificate entry is truncated.");
                var cms = new SignedCms();
                cms.Decode(payload);
                foreach (var certificate in cms.Certificates)
                {
                    if (certificates.Count >= MaximumEmbeddedCertificates)
                        throw new InvalidDataException("Embedded certificate count exceeds the safety limit.");
                    certificates.Add(new X509Certificate2(certificate.RawData));
                }

                cursor = checked(cursor + AlignEight(length));
            }

            if (cursor != end || certificates.Count == 0)
                throw new InvalidDataException("Authenticode certificate table is empty or misaligned.");
            return certificates;
        }
        catch
        {
            foreach (var certificate in certificates) certificate.Dispose();
            throw;
        }
    }

    private static long AlignEight(uint value) => checked(((long)value + 7L) & ~7L);

    private static void RequireRange(Stream stream, long offset, long length, string description)
    {
        if (offset < 0 || length < 0 || offset > stream.Length || length > stream.Length - offset)
            throw new InvalidDataException($"PE {description} is outside the file.");
    }
}
