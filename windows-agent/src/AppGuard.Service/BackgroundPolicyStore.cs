using System.Text;
using System.Text.Json;
using AppGuard.Core;

namespace AppGuard.Service;

public sealed class BackgroundPolicyStore
{
    private const string MutexName = @"Global\AppControlManager.BackgroundPolicyState";
    private readonly FileLogger _log;
    private readonly JsonSerializerOptions _json = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };

    public BackgroundPolicyStore(FileLogger log)
    {
        _log = log;
        Directory.CreateDirectory(AppGuardPaths.ProgramDataRoot);
        Directory.CreateDirectory(AppGuardPaths.RuleFragmentDirectory);
        Mutate(snapshot =>
        {
            foreach (var rule in snapshot.Rules.Where(x => x.Status == BackgroundPolicyStatuses.Processing))
            {
                rule.Status = BackgroundPolicyStatuses.Queued;
                rule.Attempts++;
                rule.LastError = "Recovered after agent restart while processing.";
                rule.UpdatedAt = Now();
            }
            foreach (var bundle in snapshot.Bundles.Where(x => x.Status == BackgroundPolicyStatuses.Processing))
            {
                bundle.Status = BackgroundPolicyStatuses.Queued;
                bundle.Attempts++;
                bundle.LastError = "Recovered after agent restart while processing.";
                bundle.UpdatedAt = Now();
            }
            return 0;
        });
    }

    public BackgroundPolicySnapshot Snapshot() => WithSnapshot(CloneSnapshot);

    public RuleCacheEntry UpsertProductCandidate(long? requestId, string ownerType, string publisher, string productName, string fileVersion, string representativePath)
    {
        var normalizedPublisher = Normalize(publisher);
        var normalizedProduct = Normalize(productName);
        var key = $"product|{normalizedPublisher}|{normalizedProduct}";
        return Mutate(snapshot =>
        {
            var entry = snapshot.Rules.FirstOrDefault(x => string.Equals(x.CacheKey, key, StringComparison.OrdinalIgnoreCase));
            if (entry is null)
            {
                entry = new RuleCacheEntry
                {
                    CacheKey = key, Kind = "product", Status = BackgroundPolicyStatuses.Queued,
                    Publisher = publisher.Trim(), ProductName = productName.Trim(), MinimumFileVersion = fileVersion,
                    RepresentativePath = representativePath
                };
                snapshot.Rules.Add(entry);
            }
            else if (IsLowerVersion(fileVersion, entry.MinimumFileVersion))
            {
                entry.MinimumFileVersion = fileVersion;
                entry.RepresentativePath = representativePath;
                entry.FragmentXmlPath = null;
                entry.Status = BackgroundPolicyStatuses.Superseded;
                entry.LastError = null;
            }
            AddOwner(entry.Owners, requestId, ownerType);
            entry.UpdatedAt = Now();
            return Clone(entry);
        });
    }

    public RuleCacheEntry UpsertHashCandidate(long? requestId, string ownerType, string sha256, string representativePath)
    {
        var hash = (sha256 ?? "").Trim().ToUpperInvariant();
        if (hash.Length == 0) throw new ArgumentException("SHA256 is required.", nameof(sha256));
        var key = $"hash|{hash}";
        return Mutate(snapshot =>
        {
            var entry = snapshot.Rules.FirstOrDefault(x => string.Equals(x.CacheKey, key, StringComparison.OrdinalIgnoreCase));
            if (entry is null)
            {
                entry = new RuleCacheEntry { CacheKey = key, Kind = "hash", Status = BackgroundPolicyStatuses.Queued, Sha256 = hash, RepresentativePath = representativePath };
                snapshot.Rules.Add(entry);
            }
            AddOwner(entry.Owners, requestId, ownerType);
            entry.UpdatedAt = Now();
            return Clone(entry);
        });
    }

    public BackgroundBundleJob QueueBundle(long requestId, long? scopedPolicyId, string applicationRoot, IReadOnlyList<BackgroundBundleMember> members, IEnumerable<string> requiredRuleKeys)
        => Mutate(snapshot =>
        {
            var existing = snapshot.Bundles.FirstOrDefault(x => x.RequestId == requestId && x.Status != BackgroundPolicyStatuses.Installed);
            var job = existing ?? new BackgroundBundleJob { RequestId = requestId };
            job.ScopedPolicyId = scopedPolicyId;
            job.ApplicationRoot = applicationRoot;
            job.Members = members.Select(Clone).ToList();
            job.RequiredRuleKeys = requiredRuleKeys.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            job.Status = BackgroundPolicyStatuses.Queued;
            job.LastError = null;
            job.UpdatedAt = Now();
            if (existing is null) snapshot.Bundles.Add(job);
            return Clone(job);
        });

    public RuleCacheEntry? ClaimNextRule()
        => Mutate(snapshot =>
        {
            var entry = snapshot.Rules.FirstOrDefault(x => (x.Status == BackgroundPolicyStatuses.Queued || x.Status == BackgroundPolicyStatuses.Superseded) && x.Attempts < 3);
            if (entry is null) return null;
            entry.Status = BackgroundPolicyStatuses.Processing;
            entry.Attempts++;
            entry.UpdatedAt = Now();
            return Clone(entry);
        });

    public void MarkRuleReady(string cacheKey, string fragmentXmlPath, string? minimumFileVersion)
        => Mutate(snapshot =>
        {
            var entry = RequireRule(snapshot, cacheKey);
            entry.Status = BackgroundPolicyStatuses.Ready;
            entry.FragmentXmlPath = fragmentXmlPath;
            if (!string.IsNullOrWhiteSpace(minimumFileVersion)) entry.MinimumFileVersion = minimumFileVersion;
            entry.LastError = null;
            entry.UpdatedAt = Now();
            return 0;
        });

    public void RequeueRule(string cacheKey, string reason)
        => Mutate(snapshot =>
        {
            var entry = RequireRule(snapshot, cacheKey);
            entry.Status = BackgroundPolicyStatuses.Queued;
            entry.Attempts = Math.Max(0, entry.Attempts - 1);
            entry.LastError = reason;
            entry.UpdatedAt = Now();
            return 0;
        });

    public void MarkRuleFailed(string cacheKey, string error)
        => Mutate(snapshot =>
        {
            var entry = RequireRule(snapshot, cacheKey);
            entry.Status = entry.Attempts >= 3 ? BackgroundPolicyStatuses.Failed : BackgroundPolicyStatuses.Queued;
            entry.LastError = error;
            entry.UpdatedAt = Now();
            return 0;
        });

    public BackgroundBundleJob? ClaimReadyBundle()
        => Mutate(snapshot =>
        {
            var readyKeys = snapshot.Rules.Where(x => x.Status == BackgroundPolicyStatuses.Ready && !string.IsNullOrWhiteSpace(x.FragmentXmlPath))
                .Select(x => x.CacheKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var bundle = snapshot.Bundles.FirstOrDefault(x => x.Status == BackgroundPolicyStatuses.Queued && x.Attempts < 3 && x.RequiredRuleKeys.All(readyKeys.Contains));
            if (bundle is null) return null;
            bundle.Status = BackgroundPolicyStatuses.Processing;
            bundle.Attempts++;
            bundle.UpdatedAt = Now();
            return Clone(bundle);
        });

    public void MarkBundleInstalled(long requestId, string policyId)
        => Mutate(snapshot => { var job = RequireBundle(snapshot, requestId); job.Status = BackgroundPolicyStatuses.Installed; job.PolicyId = policyId; job.LastError = null; job.UpdatedAt = Now(); return 0; });

    public void MarkBundleFailed(long requestId, string error)
        => Mutate(snapshot => { var job = RequireBundle(snapshot, requestId); job.Status = job.Attempts >= 3 ? BackgroundPolicyStatuses.Failed : BackgroundPolicyStatuses.Queued; job.LastError = error; job.UpdatedAt = Now(); return 0; });

    public void UpsertLearningReference(long? recordId, string filePath, string ruleKey)
        => Mutate(snapshot =>
        {
            var existing = snapshot.Learning.FirstOrDefault(x => string.Equals(x.FilePath, filePath, StringComparison.OrdinalIgnoreCase));
            if (existing is null) snapshot.Learning.Add(new LearningRuleReference { RecordId = recordId, FilePath = filePath, RuleKey = ruleKey });
            else { existing.RecordId = recordId ?? existing.RecordId; existing.RuleKey = ruleKey; }
            return 0;
        });

    public IReadOnlyList<string> LearningRuleKeysForPaths(IEnumerable<string> filePaths)
    {
        var wanted = filePaths.Where(x => !string.IsNullOrWhiteSpace(x)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return WithSnapshot(snapshot => snapshot.Learning.Where(x => wanted.Contains(x.FilePath) && !string.IsNullOrWhiteSpace(x.RuleKey)).Select(x => x.RuleKey).Distinct(StringComparer.OrdinalIgnoreCase).ToList());
    }

    public IReadOnlyList<RuleCacheEntry> RulesForKeys(IEnumerable<string> keys)
    {
        var wanted = keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return WithSnapshot(snapshot => snapshot.Rules.Where(x => wanted.Contains(x.CacheKey)).Select(Clone).ToList());
    }

    public (int Pending, int Failed, string Status) QueueStatus()
        => WithSnapshot(snapshot =>
        {
            var pending = snapshot.Rules.Count(x => x.Status is BackgroundPolicyStatuses.Queued or BackgroundPolicyStatuses.Processing or BackgroundPolicyStatuses.Superseded)
                          + snapshot.Bundles.Count(x => x.Status is BackgroundPolicyStatuses.Queued or BackgroundPolicyStatuses.Processing);
            var failed = snapshot.Rules.Count(x => x.Status == BackgroundPolicyStatuses.Failed) + snapshot.Bundles.Count(x => x.Status == BackgroundPolicyStatuses.Failed);
            var status = failed > 0 ? "failed" : pending > 0 ? "processing" : "idle";
            return (pending, failed, status);
        });

    public LearningPreparationStats PrepareLearningEvents(IEnumerable<EventUpload> events)
    {
        var stats = new LearningPreparationStats();
        foreach (var item in events.Where(x => x.EventId == 3076))
        {
            stats.Observed++;
            var filePath = (item.FilePath ?? string.Empty).Trim();
            if (filePath.Length == 0) { stats.Unpreparable++; continue; }
            RuleCacheEntry? prepared = null;
            var publisher = (item.Publisher ?? string.Empty).Trim();
            var product = (item.ProductName ?? string.Empty).Trim();
            var version = (item.FileVersion ?? string.Empty).Trim();
            if (publisher.Length > 0 && IsSafeProductName(product) && Version.TryParse(version, out _))
            {
                var key = $"product|{Normalize(publisher)}|{Normalize(product)}";
                var before = Snapshot().Rules.FirstOrDefault(x => string.Equals(x.CacheKey, key, StringComparison.OrdinalIgnoreCase));
                prepared = UpsertProductCandidate(null, "learning", publisher, product, version, filePath);
                stats.ProductCandidates++;
                CountQueueDisposition(before, prepared, stats);
            }
            else if (!string.IsNullOrWhiteSpace(item.Sha256))
            {
                var hash = item.Sha256.Trim().ToUpperInvariant();
                var before = Snapshot().Rules.FirstOrDefault(x => string.Equals(x.CacheKey, $"hash|{hash}", StringComparison.OrdinalIgnoreCase));
                prepared = UpsertHashCandidate(null, "learning", hash, filePath);
                stats.HashCandidates++;
                CountQueueDisposition(before, prepared, stats);
            }
            if (prepared is null) { stats.Unpreparable++; continue; }
            UpsertLearningReference(item.RecordId, filePath, prepared.CacheKey);
        }
        return stats;
    }

    private static void CountQueueDisposition(RuleCacheEntry? before, RuleCacheEntry after, LearningPreparationStats stats)
    {
        if (before is null || !string.Equals(before.MinimumFileVersion, after.MinimumFileVersion, StringComparison.OrdinalIgnoreCase) || after.Status == BackgroundPolicyStatuses.Superseded) stats.Queued++;
        else stats.Reused++;
    }

    private static bool IsSafeProductName(string? value)
    {
        var name = (value ?? string.Empty).Trim();
        if (name.Length < 4 || name.Length > 160) return false;
        var generic = new[] { ".NET", "Microsoft .NET", "Microsoft® .NET", "Microsoft(R) .NET", "Windows", "Microsoft Windows", "Runtime", "Application", "Setup", "Installer", "Microsoft Visual C++", "Microsoft Visual C++ Runtime" };
        if (generic.Any(x => name.Equals(x, StringComparison.OrdinalIgnoreCase))) return false;
        return !name.StartsWith("Microsoft .NET", StringComparison.OrdinalIgnoreCase) && !name.StartsWith("Microsoft® .NET", StringComparison.OrdinalIgnoreCase) && !name.StartsWith("Microsoft(R) .NET", StringComparison.OrdinalIgnoreCase) && !name.StartsWith(".NET", StringComparison.OrdinalIgnoreCase);
    }

    private T WithSnapshot<T>(Func<BackgroundPolicySnapshot, T> action)
    {
        using var mutex = new Mutex(false, MutexName);
        var acquired = false;
        try { acquired = mutex.WaitOne(TimeSpan.FromSeconds(30)); if (!acquired) throw new TimeoutException("Timed out waiting for AppControl Manager background-policy state lock."); return action(ReadUnsafe()); }
        finally { if (acquired) mutex.ReleaseMutex(); }
    }

    private T Mutate<T>(Func<BackgroundPolicySnapshot, T> action)
    {
        using var mutex = new Mutex(false, MutexName);
        var acquired = false;
        try
        {
            acquired = mutex.WaitOne(TimeSpan.FromSeconds(30));
            if (!acquired) throw new TimeoutException("Timed out waiting for AppControl Manager background-policy state lock.");
            var snapshot = ReadUnsafe();
            var result = action(snapshot);
            WriteUnsafe(snapshot);
            return result;
        }
        finally { if (acquired) mutex.ReleaseMutex(); }
    }

    private BackgroundPolicySnapshot ReadUnsafe()
    {
        try
        {
            if (!File.Exists(AppGuardPaths.BackgroundPolicyQueuePath)) return new BackgroundPolicySnapshot();
            return JsonSerializer.Deserialize<BackgroundPolicySnapshot>(File.ReadAllText(AppGuardPaths.BackgroundPolicyQueuePath, Encoding.UTF8), _json) ?? new BackgroundPolicySnapshot();
        }
        catch (Exception ex) { _log.Write("background-policy state read failed: " + ex.Message); return new BackgroundPolicySnapshot(); }
    }

    private void WriteUnsafe(BackgroundPolicySnapshot snapshot)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(AppGuardPaths.BackgroundPolicyQueuePath)!);
        var temp = AppGuardPaths.BackgroundPolicyQueuePath + ".tmp." + Guid.NewGuid().ToString("N");
        File.WriteAllText(temp, JsonSerializer.Serialize(snapshot, _json), new UTF8Encoding(false));
        File.Move(temp, AppGuardPaths.BackgroundPolicyQueuePath, true);
    }

    private static RuleCacheEntry RequireRule(BackgroundPolicySnapshot snapshot, string key)
        => snapshot.Rules.FirstOrDefault(x => string.Equals(x.CacheKey, key, StringComparison.OrdinalIgnoreCase)) ?? throw new KeyNotFoundException("Background policy rule not found: " + key);
    private static BackgroundBundleJob RequireBundle(BackgroundPolicySnapshot snapshot, long requestId)
        => snapshot.Bundles.FirstOrDefault(x => x.RequestId == requestId) ?? throw new KeyNotFoundException("Background policy bundle not found: " + requestId);
    private static string Normalize(string value) => string.Join(" ", (value ?? "").Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).ToUpperInvariant();
    private static bool IsLowerVersion(string? candidate, string? current) { if (!Version.TryParse(candidate, out var c)) return false; if (!Version.TryParse(current, out var e)) return true; return c < e; }
    private static void AddOwner(List<string> owners, long? requestId, string ownerType) { var owner = requestId.HasValue ? $"{ownerType}:{requestId.Value}" : ownerType; if (!owners.Contains(owner, StringComparer.OrdinalIgnoreCase)) owners.Add(owner); }
    private BackgroundPolicySnapshot CloneSnapshot(BackgroundPolicySnapshot value) => JsonSerializer.Deserialize<BackgroundPolicySnapshot>(JsonSerializer.Serialize(value, _json), _json) ?? new BackgroundPolicySnapshot();
    private RuleCacheEntry Clone(RuleCacheEntry value) => JsonSerializer.Deserialize<RuleCacheEntry>(JsonSerializer.Serialize(value, _json), _json)!;
    private BackgroundBundleJob Clone(BackgroundBundleJob value) => JsonSerializer.Deserialize<BackgroundBundleJob>(JsonSerializer.Serialize(value, _json), _json)!;
    private BackgroundBundleMember Clone(BackgroundBundleMember value) => JsonSerializer.Deserialize<BackgroundBundleMember>(JsonSerializer.Serialize(value, _json), _json)!;
    private static string Now() => DateTimeOffset.UtcNow.ToString("O");
}
