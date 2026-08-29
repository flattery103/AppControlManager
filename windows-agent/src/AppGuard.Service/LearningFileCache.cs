using AppGuard.Core;

namespace AppGuard.Service;

/// <summary>
/// Preserves audit-mode rule inputs before short-lived installer files disappear.
/// Cached files are never launched; they are read only by the constrained rule generator.
/// </summary>
public sealed class LearningFileCache
{
    private readonly FileLogger _log;
    private readonly object _gate = new();
    private const long MaxCacheFileBytes = 128L * 1024 * 1024;

    public LearningFileCache(FileLogger log)
    {
        _log = log;
        Directory.CreateDirectory(AppGuardPaths.LearningCacheDirectory);
        CleanupOldEntries();
    }

    public string? Capture(EventUpload item)
    {
        if (item.EventId != 3076 || !item.RecordId.HasValue || item.RecordId.Value <= 0 || string.IsNullOrWhiteSpace(item.FilePath))
            return null;
        var original = DevicePathResolver.Resolve(item.FilePath) ?? item.FilePath;
        var dir = Path.Combine(AppGuardPaths.LearningCacheDirectory, item.RecordId.Value.ToString());

        lock (_gate)
        {
            var existing = FindCached(dir);
            if (existing is not null) return existing;
            try
            {
                if (!File.Exists(original)) return null;
                var info = new FileInfo(original);
                if (info.Length > MaxCacheFileBytes)
                {
                    _log.Write($"learning-cache skipped-large record={item.RecordId.Value} bytes={info.Length} file={original}");
                    return null;
                }
                Directory.CreateDirectory(dir);
                var name = Path.GetFileName(original);
                if (string.IsNullOrWhiteSpace(name)) name = "observed.bin";
                var cached = Path.Combine(dir, name);
                using var input = new FileStream(original, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var output = new FileStream(cached, FileMode.Create, FileAccess.Write, FileShare.Read);
                input.CopyTo(output);
                _log.Write($"learning-cache captured record={item.RecordId.Value} file={original}");
                return cached;
            }
            catch (Exception ex)
            {
                _log.Write($"learning-cache capture failed record={item.RecordId.Value} file={original}: {ex.Message}");
                return null;
            }
        }
    }

    public string? Resolve(long? recordId, string livePath)
    {
        if (!string.IsNullOrWhiteSpace(livePath) && File.Exists(livePath)) return livePath;
        if (!recordId.HasValue || recordId.Value <= 0) return null;
        return FindCached(Path.Combine(AppGuardPaths.LearningCacheDirectory, recordId.Value.ToString()));
    }

    private static string? FindCached(string directory)
    {
        if (!Directory.Exists(directory)) return null;
        try { return Directory.EnumerateFiles(directory).FirstOrDefault(File.Exists); }
        catch { return null; }
    }

    private void CleanupOldEntries()
    {
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(AppGuardPaths.LearningCacheDirectory))
                if (DateTime.UtcNow - Directory.GetLastWriteTimeUtc(dir) > TimeSpan.FromDays(2)) Directory.Delete(dir, true);
        }
        catch (Exception ex) { _log.Write("learning-cache cleanup: " + ex.Message); }
    }
}
