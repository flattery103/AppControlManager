using System.Text.Json;
using AppGuard.Core;

namespace AppGuard.Service;

/// <summary>
/// Preserves a short-lived copy of a blocked file as soon as Event 3077 is seen.
/// Installers frequently create temporary payloads that disappear before a user can click Request Access.
/// The cached copy is never executed; it is used only to read signer/hash metadata and generate a WDAC rule.
/// </summary>
public sealed class BlockedFileCache
{
    private readonly FileLogger _log;
    private readonly object _gate = new();
    private const long MaxCacheFileBytes = 128L * 1024 * 1024;

    public BlockedFileCache(FileLogger log)
    {
        _log = log;
        Directory.CreateDirectory(AppGuardPaths.BlockCacheDirectory);
        CleanupOldEntries();
    }

    public BlockedSnapshot Capture(long recordId, string filePath, string? parentPath)
    {
        var original = DevicePathResolver.Resolve(filePath) ?? filePath;
        var parent = DevicePathResolver.Resolve(parentPath);
        if (recordId <= 0) recordId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        lock (_gate)
        {
            var existing = Get(recordId);
            if (existing is not null) return existing;

            string? cached = null;
            var dir = Path.Combine(AppGuardPaths.BlockCacheDirectory, recordId.ToString());
            Directory.CreateDirectory(dir);

            try
            {
                if (File.Exists(original))
                {
                    var info = new FileInfo(original);
                    if (info.Length <= MaxCacheFileBytes)
                    {
                        var name = Path.GetFileName(original);
                        if (string.IsNullOrWhiteSpace(name)) name = "blocked.bin";
                        cached = Path.Combine(dir, name);
                        // Read with sharing that tolerates installer temp files being open or marked for deletion.
                        using var input = new FileStream(original, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                        using var output = new FileStream(cached, FileMode.Create, FileAccess.Write, FileShare.Read);
                        input.CopyTo(output);
                        _log.Write($"block-cache captured record={recordId} file={original}");
                    }
                    else
                    {
                        _log.Write($"block-cache skipped-large record={recordId} bytes={info.Length} file={original}");
                    }
                }
            }
            catch (Exception ex)
            {
                _log.Write($"block-cache capture failed record={recordId} file={original}: {ex.Message}");
                cached = null;
            }

            // Prefer the preserved copy for metadata because the original temp path may already be gone.
            var meta = FileMetadataReader.Read(cached ?? original);

            var snapshot = new BlockedSnapshot
            {
                RecordId = recordId,
                OriginalPath = original,
                ParentPath = parent,
                CachedPath = cached,
                Sha256 = meta.Sha256,
                Publisher = meta.Publisher,
                ProductName = meta.ProductName,
                FileVersion = meta.FileVersion,
                CapturedAt = DateTimeOffset.UtcNow.ToString("O")
            };
            Save(snapshot);
            return snapshot;
        }
    }

    public BlockedSnapshot? Get(long recordId)
    {
        if (recordId <= 0) return null;
        var json = Path.Combine(AppGuardPaths.BlockCacheDirectory, recordId.ToString(), "snapshot.json");
        if (!File.Exists(json)) return null;
        try
        {
            return JsonSerializer.Deserialize<BlockedSnapshot>(File.ReadAllText(json), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch { return null; }
    }

    private static void Save(BlockedSnapshot snapshot)
    {
        var dir = Path.Combine(AppGuardPaths.BlockCacheDirectory, snapshot.RecordId.ToString());
        Directory.CreateDirectory(dir);
        var json = Path.Combine(dir, "snapshot.json");
        File.WriteAllText(json, JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true }));
    }

    private void CleanupOldEntries()
    {
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(AppGuardPaths.BlockCacheDirectory))
            {
                var age = DateTime.UtcNow - Directory.GetLastWriteTimeUtc(dir);
                if (age > TimeSpan.FromDays(2)) Directory.Delete(dir, true);
            }
        }
        catch (Exception ex) { _log.Write("block-cache cleanup: " + ex.Message); }
    }
}
