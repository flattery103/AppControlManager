using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AppGuard.Core;

public sealed record FileMetadata(string FilePath, string? Sha256, string? Publisher, string? ProductName, string? FileVersion);

public static class DevicePathResolver
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    public static string? Resolve(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return path;
        var p = path.Replace(@"\\?\", "", StringComparison.OrdinalIgnoreCase);
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), p[12..]);
        if (!p.StartsWith(@"\Device\HarddiskVolume", StringComparison.OrdinalIgnoreCase)) return p;

        for (char c = 'A'; c <= 'Z'; c++)
        {
            var drive = $"{c}:";
            if (!Directory.Exists(drive + @"\")) continue;
            var sb = new StringBuilder(1024);
            if (QueryDosDevice(drive, sb, sb.Capacity) == 0) continue;
            var target = sb.ToString().Split('\0')[0];
            if (p.StartsWith(target, StringComparison.OrdinalIgnoreCase))
                return drive + p[target.Length..];
        }
        return p;
    }
}

public static class FileMetadataReader
{
    public static FileMetadata Read(string path)
    {
        var resolved = DevicePathResolver.Resolve(path) ?? path;
        if (!File.Exists(resolved)) return new(resolved, null, null, null, null);
        string? hash = null, publisher = null, product = null, version = null;
        try
        {
            using var stream = File.OpenRead(resolved);
            hash = Convert.ToHexString(SHA256.HashData(stream));
        }
        catch { }
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(resolved);
            using var cert2 = new X509Certificate2(cert);
            publisher = cert2.Subject;
        }
        catch { }
        try
        {
            var info = FileVersionInfo.GetVersionInfo(resolved);
            product = info.ProductName;
            version = info.FileVersion;
        }
        catch { }
        return new(resolved, hash, publisher, product, version);
    }
}
