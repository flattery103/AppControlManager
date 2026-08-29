using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AppGuard.Core;

public static class WorkerOutputSnapshot
{
    public const long MaximumPolicyBytes = 32L * 1024 * 1024;
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
    private const uint FILE_NAME_NORMALIZED = 0x0;
    private const uint VOLUME_NAME_DOS = 0x0;
    private const int FileAttributeTagInfoClass = 9;

    public static string CopyExactToProtected(string openPath, string expectedFinalPath, string protectedDirectory)
    {
        var expected = NormalizeWindowsPath(Path.GetFullPath(expectedFinalPath));
        var protectedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(protectedDirectory));
        var snapshot = Path.Combine(protectedRoot, ".worker-snapshot-" + Guid.NewGuid().ToString("N") + ".xml");
        using var handle = CreateFileW(
            Path.GetFullPath(openPath),
            GENERIC_READ,
            FILE_SHARE_READ,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            IntPtr.Zero);
        if (handle.IsInvalid)
            throw new IOException("Could not open the fixed rule-worker output.", new Win32Exception(Marshal.GetLastWin32Error()));
        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, out var tagInfo, (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
            throw new IOException("Could not inspect the opened rule-worker output.", new Win32Exception(Marshal.GetLastWin32Error()));
        if ((tagInfo.FileAttributes & FileAttributes.ReparsePoint) != 0 ||
            (tagInfo.FileAttributes & FileAttributes.Directory) != 0)
            throw new InvalidDataException("Opened rule-worker output must be an ordinary non-reparse file.");

        var finalPath = NormalizeWindowsPath(GetFinalPath(handle));
        if (!finalPath.Equals(expected, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetDirectoryName(finalPath), Path.GetDirectoryName(expected), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Opened rule-worker output did not resolve to the exact fixed job output.");

        try
        {
            using var source = new FileStream(handle, FileAccess.Read);
            if (source.Length <= 0 || source.Length > MaximumPolicyBytes)
                throw new InvalidDataException("Rule worker output size is invalid.");
            using var destination = new FileStream(snapshot, FileMode.CreateNew, FileAccess.Write, FileShare.None, 128 * 1024, FileOptions.WriteThrough);
            source.CopyTo(destination);
            destination.Flush(true);
            return snapshot;
        }
        catch
        {
            try { File.Delete(snapshot); } catch { }
            throw;
        }
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        var capacity = 512;
        while (true)
        {
            var buffer = new StringBuilder(capacity);
            var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            if (length == 0)
                throw new IOException("Could not resolve the opened rule-worker output path.", new Win32Exception(Marshal.GetLastWin32Error()));
            if (length < buffer.Capacity) return buffer.ToString();
            capacity = checked((int)length + 1);
        }
    }

    private static string NormalizeWindowsPath(string path)
    {
        var value = path;
        if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) value = @"\\" + value[8..];
        else if (value.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)) value = value[4..];
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(value));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public FileAttributes FileAttributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        int fileInformationClass,
        out FileAttributeTagInfo fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);
}
