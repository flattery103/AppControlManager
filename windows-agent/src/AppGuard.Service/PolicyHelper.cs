using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using System.Text;
using System.Security.Cryptography;
using AppGuard.Core;

namespace AppGuard.Service;

public sealed class PolicyHelper
{
    private readonly FileLogger _log;
    private readonly PolicyProgressTracker _progress;
    private readonly BackgroundPolicyStore _backgroundStore;
    private readonly RuleWorkerClient _ruleWorker;
    private readonly ConcurrentDictionary<string, PublisherCacheEntry> _publisherCache = new(StringComparer.OrdinalIgnoreCase);
    private const int PublisherCacheLimit = 5000;
    private readonly SemaphoreSlim _policyGenerationGate = new(1, 1);
    private volatile int _foregroundWaiters;
    public bool ForegroundPending => Volatile.Read(ref _foregroundWaiters) > 0;

    public PolicyHelper(FileLogger log, PolicyProgressTracker progress, BackgroundPolicyStore backgroundStore, RuleWorkerClient ruleWorker)
    {
        _log = log;
        _progress = progress;
        _backgroundStore = backgroundStore;
        _ruleWorker = ruleWorker;
    }

    public Task<SupplementalResult> ApproveFileAsync(string filePath, long requestId, CancellationToken ct)
        => ApproveFilesAsync([filePath], requestId, null, ct);

    public Task<SupplementalResult> ApproveFileAsync(string filePath, long requestId, long? scopedPolicyId, CancellationToken ct)
        => ApproveFilesAsync([filePath], requestId, scopedPolicyId, ct);

    public Task<SupplementalResult> ApproveFilesAsync(IReadOnlyList<string> filePaths, long requestId, CancellationToken ct)
        => ApproveFilesAsync(filePaths, requestId, null, ct);

    public async Task<SupplementalResult> PreauthorizeAgentUpdateAsync(IReadOnlyList<string> filePaths, long requestId, CancellationToken ct)
    {
        var files = filePaths.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (files.Length != filePaths.Count || files.Length == 0)
            throw new FileNotFoundException("One or more replacement agent binaries are unavailable for update preauthorization.");

        Interlocked.Increment(ref _foregroundWaiters);
        try
        {
            await _policyGenerationGate.WaitAsync(ct);
            try
            {
                Directory.CreateDirectory(AppGuardPaths.RuleFragmentDirectory);
                var fragments = new List<string>();
                foreach (var file in files)
                {
                    var fragment = Path.Combine(AppGuardPaths.RuleFragmentDirectory, $"Update-{Guid.NewGuid():N}.xml");
                    _log.Write($"agent-update hash preauthorization start request={requestId} file={file}");
                    await _ruleWorker.GenerateAsync("hash", file, fragment, ct);
                    fragments.Add(fragment);
                }

                var listPath = Path.Combine(Path.GetTempPath(), $"AppControlManager-UpdateFragments-{Guid.NewGuid():N}.json");
                try
                {
                    await File.WriteAllTextAsync(listPath, JsonSerializer.Serialize(fragments), new UTF8Encoding(false), ct);
                    var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "Install-MergedSupplemental.ps1");
                    var args = $"-FragmentListPath {Quote(listPath)} -Name {Quote("AppControl Manager Update " + Math.Abs(requestId))} -Json";
                    var output = await RunPowerShellAsync(script, args, ct);
                    var line = output.Split(['\r','\n'], StringSplitOptions.RemoveEmptyEntries).LastOrDefault(x => x.TrimStart().StartsWith("{"));
                    if (line is null) throw new InvalidOperationException("Update preauthorization helper did not return JSON. Output: " + output);
                    var result = JsonSerializer.Deserialize<SupplementalResult>(line, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                                 ?? throw new InvalidOperationException("Could not parse update preauthorization result.");
                    result.RequestedFiles = files.Length;
                    result.PolicyFiles = files.Length;
                    result.PrimaryRuleMode = "hash";
                    _log.Write($"agent-update hash preauthorization finished request={requestId} files={files.Length} policy={result.PolicyId}");
                    return result;
                }
                finally { try { File.Delete(listPath); } catch { } }
            }
            finally { _policyGenerationGate.Release(); }
        }
        finally { Interlocked.Decrement(ref _foregroundWaiters); }
    }

    public async Task<SupplementalResult> ApproveFilesAsync(IReadOnlyList<string> filePaths, long requestId, long? scopedPolicyId, CancellationToken ct)
    {
        var requested = filePaths.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (requested.Length == 0) throw new FileNotFoundException("None of the approved component files are available for policy generation.");

        var primaryFile = requested[0];
        _progress.Update(requestId, "discovering", "Scanning the installed application for related signed components...", requested.Length);
        var expansion = ExpandProtectedApplicationBundles(requested);
        var files = expansion.Files;
        var expanded = Math.Max(files.Length - requested.Length, 0);
        _log.Write($"bundle-scan summary requested={requested.Length} policyFiles={files.Length} expanded={expanded} roots={expansion.RootScans} duplicateRootsSkipped={expansion.DuplicateScansSkipped} filesExamined={expansion.FilesExamined} signerReads={expansion.SignerReads} cacheHits={expansion.CacheHits} scanElapsed={expansion.ScanElapsed.TotalSeconds:F2}s primary={primaryFile}");

        _progress.Update(requestId, "authorizing_primary", "Authorizing primary application...", 1);
        Directory.CreateDirectory(AppGuardPaths.PolicyDirectory);
        var generatedXml = Path.Combine(AppGuardPaths.PolicyDirectory, $"Primary-{Guid.NewGuid():N}.xml");
        RuleWorkerResult generated;
        string output;
        var started = DateTimeOffset.UtcNow;
        Interlocked.Increment(ref _foregroundWaiters);
        try
        {
            await _policyGenerationGate.WaitAsync(ct);
            try
            {
                _log.Write($"policy-helper primary start request={requestId} files=1 primary={primaryFile}");
                generated = await _ruleWorker.GenerateAsync("primary_allow", primaryFile, generatedXml, ct);
                var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "Install-GeneratedPolicy.ps1");
                var args = $"-Operation primary_allow -XmlPath {Quote(generatedXml)} -Name {Quote("AppControl Manager Approval " + requestId)} -RuleMode {Quote(generated.RuleMode)} -Json";
                output = await RunPowerShellAsync(script, args, ct);
            }
            finally { _policyGenerationGate.Release(); }
        }
        finally { Interlocked.Decrement(ref _foregroundWaiters); }

        _log.Write($"policy-helper primary finished request={requestId} files=1 elapsed={(DateTimeOffset.UtcNow - started).TotalSeconds:F1}s");
        var line = output.Split(['\r','\n'], StringSplitOptions.RemoveEmptyEntries).LastOrDefault(x => x.TrimStart().StartsWith("{"));
        if (line is null) throw new InvalidOperationException("Primary policy helper did not return JSON. Output: " + output);
        var result = JsonSerializer.Deserialize<SupplementalResult>(line, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                     ?? throw new InvalidOperationException("Could not parse primary policy helper result.");
        ApplyWorkerMetadata(result, generated, includePrimaryMode: true);
        result.RequestedFiles = requested.Length;
        result.PolicyFiles = 1;
        result.ExpandedFiles = expanded;
        _progress.Update(requestId, "approved", "Primary authorization installed; preparing remaining application components in background.", 1);
        result.BackgroundQueued = QueueBackgroundBundle(requestId, scopedPolicyId, expansion, result);
        return result;
    }

    public async Task<T> RunSerializedBackgroundAsync<T>(Func<CancellationToken, Task<T>> action, CancellationToken ct)
    {
        if (ForegroundPending) throw new InvalidOperationException("foreground policy generation is pending");
        await _policyGenerationGate.WaitAsync(ct);
        try
        {
            if (ForegroundPending) throw new InvalidOperationException("foreground policy generation is pending");
            return await action(ct);
        }
        finally { _policyGenerationGate.Release(); }
    }

    private bool QueueBackgroundBundle(long requestId, long? scopedPolicyId, BundleExpansionResult expansion, SupplementalResult primary)
    {
        if (string.IsNullOrWhiteSpace(primary.FilePath) || string.IsNullOrWhiteSpace(primary.Publisher)) return false;
        var primaryPublisher = NormalizePublisher(primary.Publisher);
        var primaryProduct = NormalizeProduct(primary.ProductName);
        var root = expansion.ApplicationRoot;
        if (string.IsNullOrWhiteSpace(root)) return false;
        var members = new List<BackgroundBundleMember>();
        var requiredKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var productGroups = 0; var hashFiles = 0; var primaryCovered = 0; var cached = 0; var queued = 0;
        foreach (var identity in expansion.Identities)
        {
            if (identity.FilePath.Equals(primary.FilePath, StringComparison.OrdinalIgnoreCase)) continue;
            if (!IsSameOrDescendantRoot(identity.FilePath, root)) continue;
            if (string.IsNullOrWhiteSpace(identity.Publisher) || !NormalizePublisher(identity.Publisher).Equals(primaryPublisher, StringComparison.OrdinalIgnoreCase)) continue;
            var product = NormalizeProduct(identity.ProductName);
            RuleCacheEntry entry;
            if (IsSafeProductName(identity.ProductName) && product.Equals(primaryProduct, StringComparison.OrdinalIgnoreCase)) { primaryCovered++; continue; }
            if (IsSafeProductName(identity.ProductName))
            {
                entry = _backgroundStore.UpsertProductCandidate(requestId, "request", identity.Publisher, identity.ProductName!, identity.FileVersion ?? "0.0.0.0", identity.FilePath);
                productGroups++;
            }
            else
            {
                var sha = identity.Sha256 ?? ComputeSha256(identity.FilePath);
                entry = _backgroundStore.UpsertHashCandidate(requestId, "request", sha, identity.FilePath);
                hashFiles++;
            }
            if (entry.Status == BackgroundPolicyStatuses.Ready) cached++; else queued++;
            requiredKeys.Add(entry.CacheKey);
            members.Add(new BackgroundBundleMember { FilePath=identity.FilePath, Publisher=identity.Publisher, ProductName=identity.ProductName, FileVersion=identity.FileVersion, Sha256=identity.Sha256, RuleKey=entry.CacheKey });
        }
        if (requiredKeys.Count > 0) _backgroundStore.QueueBundle(requestId, scopedPolicyId, root, members, requiredKeys);
        _log.Write($"bundle-background queued request={requestId} root={root} discovered={expansion.Identities.Count} primaryCovered={primaryCovered} productGroups={productGroups} hashFiles={hashFiles} cached={cached} queued={queued}");
        return requiredKeys.Count > 0;
    }

    private BundleExpansionResult ExpandProtectedApplicationBundles(IReadOnlyList<string> requested)
    {
        var stopwatch = Stopwatch.StartNew();
        var output = new HashSet<string>(requested, StringComparer.OrdinalIgnoreCase);
        var scanKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var scanTargets = new List<BundleScanTarget>();
        var filesExamined = 0;
        var signerReads = 0;
        var cacheHits = 0;
        var duplicateScansSkipped = 0;
        var rootScans = 0;

        // Resolve each requested component to an application root and publisher first. Multiple
        // components from the same signed application can otherwise trigger the same directory
        // walk repeatedly during a single approval session.
        foreach (var file in requested)
        {
            if (!IsProtectedProgramFilesPath(file)) continue;

            var primaryPublisher = GetPublisherCached(file, ref signerReads, ref cacheHits);
            if (string.IsNullOrWhiteSpace(primaryPublisher)) continue;

            var root = Path.GetDirectoryName(file);
            if (string.IsNullOrWhiteSpace(root)) continue;
            var leaf = Path.GetFileName(root);
            if (LooksLikeVersionDirectory(leaf))
            {
                var parent = Directory.GetParent(root)?.FullName;
                if (!string.IsNullOrWhiteSpace(parent) && IsProtectedProgramFilesPath(parent)) root = parent;
            }

            root = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var normalizedPublisher = NormalizePublisher(primaryPublisher);
            var scanKey = root + "|" + normalizedPublisher;
            if (!scanKeys.Add(scanKey))
            {
                duplicateScansSkipped++;
                continue;
            }
            scanTargets.Add(new BundleScanTarget(root, primaryPublisher, normalizedPublisher, file));
        }

        // Parent application roots cover their child directories. Process shorter roots first so
        // a request containing both an EXE and DLL from the same tree performs one scan, not one
        // scan per component/subdirectory.
        var coveredRoots = new List<(string Root, string Publisher)>();
        foreach (var target in scanTargets.OrderBy(x => x.Root.Length).ThenBy(x => x.Root, StringComparer.OrdinalIgnoreCase))
        {
            if (coveredRoots.Any(x => PublisherEquals(x.Publisher, target.Publisher) && IsSameOrDescendantRoot(target.Root, x.Root)))
            {
                duplicateScansSkipped++;
                _log.Write($"bundle-scan skip-covered root={target.Root} publisher={target.Publisher} primary={target.PrimaryFile}");
                continue;
            }

            var matched = 0;
            rootScans++;
            foreach (var candidate in EnumerateExecutableFiles(target.Root, maxDepth: 4, maxFiles: 750))
            {
                filesExamined++;
                var publisher = GetPublisherCached(candidate, ref signerReads, ref cacheHits);
                if (string.IsNullOrWhiteSpace(publisher)) continue;
                if (!PublisherEquals(target.Publisher, publisher)) continue;
                if (output.Add(candidate)) matched++;
            }
            coveredRoots.Add((target.Root, target.NormalizedPublisher));
            _log.Write($"bundle-scan root={target.Root} publisher={target.Publisher} matched={matched} primary={target.PrimaryFile}");
        }

        stopwatch.Stop();
        var scanElapsed = stopwatch.Elapsed;
        var identities = new List<BundleFileIdentity>();
        foreach (var file in output)
        {
            var identity = BuildBundleIdentity(file, ref signerReads, ref cacheHits);
            if (identity is not null) identities.Add(identity);
        }
        var primaryRoot = scanTargets.FirstOrDefault(x => x.PrimaryFile.Equals(requested[0], StringComparison.OrdinalIgnoreCase))?.Root
                          ?? scanTargets.FirstOrDefault()?.Root
                          ?? Path.GetDirectoryName(requested[0]);
        return new BundleExpansionResult(output.ToArray(), identities, primaryRoot, filesExamined, signerReads, cacheHits, rootScans, duplicateScansSkipped, scanElapsed);
    }

    private string? GetPublisherCached(string file, ref int signerReads, ref int cacheHits)
    {
        string fullPath;
        FileInfo info;
        try
        {
            fullPath = Path.GetFullPath(file);
            info = new FileInfo(fullPath);
            if (!info.Exists) return null;
        }
        catch
        {
            return null;
        }

        var size = info.Length;
        var lastWriteUtcTicks = info.LastWriteTimeUtc.Ticks;
        if (_publisherCache.TryGetValue(fullPath, out var cached) &&
            cached.Size == size && cached.LastWriteUtcTicks == lastWriteUtcTicks)
        {
            cacheHits++;
            return cached.Publisher;
        }

        signerReads++;
        var publisher = ReadPublisherOnly(fullPath);
        _publisherCache[fullPath] = new PublisherCacheEntry(size, lastWriteUtcTicks, publisher);

        // Keep this strictly an optimization cache, not durable state. Clearing it at a generous
        // bound is cheap and avoids unbounded growth on endpoints that process many installers.
        if (_publisherCache.Count > PublisherCacheLimit)
            _publisherCache.Clear();

        return publisher;
    }

    private static bool IsSameOrDescendantRoot(string candidate, string ancestor)
    {
        if (candidate.Equals(ancestor, StringComparison.OrdinalIgnoreCase)) return true;
        return candidate.StartsWith(ancestor + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
               candidate.StartsWith(ancestor + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private sealed record PublisherCacheEntry(long Size, long LastWriteUtcTicks, string? Publisher);
    private sealed record BundleScanTarget(string Root, string Publisher, string NormalizedPublisher, string PrimaryFile);
    private sealed record BundleFileIdentity(string FilePath, string Publisher, string? ProductName, string? FileVersion, string? Sha256);
    private sealed record BundleExpansionResult(
        string[] Files,
        IReadOnlyList<BundleFileIdentity> Identities,
        string? ApplicationRoot,
        int FilesExamined,
        int SignerReads,
        int CacheHits,
        int RootScans,
        int DuplicateScansSkipped,
        TimeSpan ScanElapsed);

    private static bool IsProtectedProgramFilesPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        string full;
        try { full = Path.GetFullPath(path); } catch { return false; }
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetEnvironmentVariable("ProgramW6432") ?? string.Empty
        }.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots)
        {
            string r;
            try { r = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar); } catch { continue; }
            if (full.StartsWith(r + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static bool LooksLikeVersionDirectory(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        var parts = name.Split('.');
        return parts.Length >= 2 && parts.Length <= 6 && parts.All(p => p.Length > 0 && p.All(char.IsDigit));
    }

    private static IEnumerable<string> EnumerateExecutableFiles(string root, int maxDepth, int maxFiles)
    {
        // Do not use yield return inside a try block that has a catch clause.
        // Collect candidates instead so inaccessible files/directories can be skipped safely.
        var extensions = new HashSet<string>(new[] { ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".com" }, StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<(string Path, int Depth)>();
        var results = new List<string>();
        queue.Enqueue((root, 0));

        while (queue.Count > 0 && results.Count < maxFiles)
        {
            var (dir, depth) = queue.Dequeue();

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir).ToArray();
            }
            catch
            {
                files = Array.Empty<string>();
            }

            foreach (var file in files)
            {
                if (results.Count >= maxFiles) break;
                if (!extensions.Contains(Path.GetExtension(file))) continue;
                results.Add(file);
            }

            if (depth >= maxDepth) continue;

            IEnumerable<string> directories;
            try
            {
                directories = Directory.EnumerateDirectories(dir).ToArray();
            }
            catch
            {
                directories = Array.Empty<string>();
            }

            foreach (var directory in directories)
                queue.Enqueue((directory, depth + 1));
        }

        return results;
    }

    private BundleFileIdentity? BuildBundleIdentity(string file, ref int signerReads, ref int cacheHits)
    {
        if (!File.Exists(file)) return null;
        var publisher = GetPublisherCached(file, ref signerReads, ref cacheHits);
        if (string.IsNullOrWhiteSpace(publisher)) return null;
        try
        {
            var info = FileVersionInfo.GetVersionInfo(file);
            return new BundleFileIdentity(file, publisher, info.ProductName, info.FileVersion, null);
        }
        catch { return new BundleFileIdentity(file, publisher, null, null, null); }
    }

    private static bool IsSafeProductName(string? value)
    {
        var name = (value ?? string.Empty).Trim();
        if (name.Length < 4 || name.Length > 160) return false;
        var generic = new[] { ".NET", "Microsoft .NET", "Microsoft® .NET", "Microsoft(R) .NET", "Windows", "Microsoft Windows", "Runtime", "Application", "Setup", "Installer", "Microsoft Visual C++", "Microsoft Visual C++ Runtime" };
        if (generic.Any(x => name.Equals(x, StringComparison.OrdinalIgnoreCase))) return false;
        return !name.StartsWith("Microsoft .NET", StringComparison.OrdinalIgnoreCase) && !name.StartsWith("Microsoft® .NET", StringComparison.OrdinalIgnoreCase) && !name.StartsWith("Microsoft(R) .NET", StringComparison.OrdinalIgnoreCase) && !name.StartsWith(".NET", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeProduct(string? value)
        => string.Join(" ", (value ?? string.Empty).Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).ToUpperInvariant();

    private static string ComputeSha256(string file)
    {
        using var stream = File.OpenRead(file);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string? ReadPublisherOnly(string file)
    {
        try
        {
            var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(file);
            using var cert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert);
            return cert2.Subject?.Trim();
        }
        catch { return null; }
    }

    private static bool PublisherEquals(string a, string b)
        => NormalizePublisher(a).Equals(NormalizePublisher(b), StringComparison.OrdinalIgnoreCase);

    private static string NormalizePublisher(string value)
        => string.Join(",", value.Split(',').Select(x => x.Trim()).Where(x => x.Length > 0));

    public async Task<BackgroundRuleFragmentResult> GenerateRuleFragmentAsync(RuleCacheEntry rule, CancellationToken ct)
        => await RunSerializedBackgroundAsync(async innerCt => await GenerateRuleFragmentCoreAsync(rule, innerCt), ct);

    public async Task<BackgroundRuleFragmentResult> GenerateRuleFragmentForegroundAsync(RuleCacheEntry rule, CancellationToken ct)
    {
        Interlocked.Increment(ref _foregroundWaiters);
        try
        {
            await _policyGenerationGate.WaitAsync(ct);
            try { return await GenerateRuleFragmentCoreAsync(rule, ct); }
            finally { _policyGenerationGate.Release(); }
        }
        finally { Interlocked.Decrement(ref _foregroundWaiters); }
    }

    private async Task<BackgroundRuleFragmentResult> GenerateRuleFragmentCoreAsync(RuleCacheEntry rule, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(rule.RepresentativePath) || !File.Exists(rule.RepresentativePath))
            throw new FileNotFoundException("Background rule representative file is no longer available.", rule.RepresentativePath);
        Directory.CreateDirectory(AppGuardPaths.RuleFragmentDirectory);
        var safe = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rule.CacheKey))).Substring(0, 24);
        var outputPath = Path.Combine(AppGuardPaths.RuleFragmentDirectory, safe + ".xml");
        var started = DateTimeOffset.UtcNow;
        var generated = await _ruleWorker.GenerateAsync(rule.Kind, rule.RepresentativePath, outputPath, ct);
        return new BackgroundRuleFragmentResult
        {
            FragmentXmlPath = outputPath,
            RuleCount = generated.RuleCount,
            Kind = generated.Operation,
            ElapsedSeconds = generated.ElapsedSeconds > 0 ? generated.ElapsedSeconds : (DateTimeOffset.UtcNow - started).TotalSeconds
        };
    }

    public async Task<SupplementalResult> InstallMergedSupplementalAsync(long requestId, IReadOnlyList<string> fragments, CancellationToken ct)
        => await RunSerializedBackgroundAsync(async innerCt =>
        {
            if (fragments.Count == 0) throw new InvalidOperationException("No ready rule fragments were supplied for background bundle installation.");
            var listPath = Path.Combine(Path.GetTempPath(), $"AppControlManager-Fragments-{Guid.NewGuid():N}.json");
            try
            {
                await File.WriteAllTextAsync(listPath, JsonSerializer.Serialize(fragments), new UTF8Encoding(false), innerCt);
                var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "Install-MergedSupplemental.ps1");
                var args = $"-FragmentListPath {Quote(listPath)} -Name {Quote("AppControl Manager Background " + requestId)} -Json";
                var output = await RunPowerShellAsync(script, args, innerCt);
                var line = output.Split(['\r','\n'], StringSplitOptions.RemoveEmptyEntries).LastOrDefault(x => x.TrimStart().StartsWith("{"));
                if (line is null) throw new InvalidOperationException("Background bundle helper did not return JSON. Output: " + output);
                return JsonSerializer.Deserialize<SupplementalResult>(line, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                       ?? throw new InvalidOperationException("Could not parse background bundle helper result.");
            }
            finally { try { File.Delete(listPath); } catch { } }
        }, ct);

    public async Task<SupplementalResult> BlockFileAsync(string filePath, long blockId, CancellationToken ct)
    {
        if (!File.Exists(filePath)) throw new FileNotFoundException("The file to block is no longer available for policy generation.", filePath);
        Directory.CreateDirectory(AppGuardPaths.PolicyDirectory);
        var generatedXml = Path.Combine(AppGuardPaths.PolicyDirectory, $"Deny-{Guid.NewGuid():N}.xml");
        RuleWorkerResult generated;
        string output;
        Interlocked.Increment(ref _foregroundWaiters);
        try
        {
            await _policyGenerationGate.WaitAsync(ct);
            try
            {
                generated = await _ruleWorker.GenerateAsync("deny_policy", filePath, generatedXml, ct);
                var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "Install-GeneratedPolicy.ps1");
                var args = $"-Operation deny_policy -XmlPath {Quote(generatedXml)} -Name {Quote("AppControl Manager Deny " + blockId)} -RuleMode {Quote(generated.RuleMode)} -Json";
                output = await RunPowerShellAsync(script, args, ct);
            }
            finally { _policyGenerationGate.Release(); }
        }
        finally { Interlocked.Decrement(ref _foregroundWaiters); }
        var line = output.Split(['\r','\n'], StringSplitOptions.RemoveEmptyEntries).LastOrDefault(x => x.TrimStart().StartsWith("{"));
        if (line is null) throw new InvalidOperationException("Deny policy helper did not return JSON. Output: " + output);
        var result = JsonSerializer.Deserialize<SupplementalResult>(line, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                     ?? throw new InvalidOperationException("Could not parse deny policy helper result.");
        ApplyWorkerMetadata(result, generated, includePrimaryMode: false);
        return result;
    }

    private static void ApplyWorkerMetadata(SupplementalResult result, RuleWorkerResult generated, bool includePrimaryMode)
    {
        result.FilePath = generated.FilePath;
        result.Sha256 = generated.Sha256;
        result.Publisher = generated.Publisher;
        result.ProductName = generated.ProductName;
        result.FileVersion = generated.FileVersion;
        if (includePrimaryMode) result.PrimaryRuleMode = generated.RuleMode;
    }

    public async Task RemovePolicyAsync(string policyId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(policyId)) throw new InvalidOperationException("Policy ID was empty.");
        var remove = await RunProcessAsync("CiTool.exe", $"--remove-policy {policyId} -json", ct);
        if (remove.ExitCode != 0) throw new InvalidOperationException($"CiTool remove-policy failed ({remove.ExitCode}): {remove.Stderr} {remove.Stdout}".Trim());
        var refresh = await RunProcessAsync("CiTool.exe", "--refresh -json", ct);
        if (refresh.ExitCode != 0) throw new InvalidOperationException($"CiTool refresh failed ({refresh.ExitCode}): {refresh.Stderr} {refresh.Stdout}".Trim());
    }

    public async Task ReturnToLearningAsync(CancellationToken ct)
    {
        await _policyGenerationGate.WaitAsync(ct);
        try
        {
            var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "Start-LearningMode.ps1");
            await RunPowerShellAsync(script, "-NoTaskControl", ct);
        }
        finally { _policyGenerationGate.Release(); }
    }

    public async Task EnableEnforcementAsync(CancellationToken ct)
    {
        _log.Write("enforcement-progress started");
        var finalDeltaTimer = Stopwatch.StartNew();
        Interlocked.Increment(ref _foregroundWaiters);
        try
        {
            await _policyGenerationGate.WaitAsync(ct);
            try
            {
                // Final reconciliation is intentionally retained: reading the 3076 snapshot has
                // measured at only ~8 seconds and catches anything not yet uploaded by maintenance.
                var collectScript = Path.Combine(AppGuardPaths.ScriptsDirectory, "Get-LearnedApplications.ps1");
                await RunPowerShellAsync(collectScript, "-Save", ct);
                var learned = ReadLearnedApplications();
                var prep = _backgroundStore.PrepareLearningEvents(learned);
                if (prep.Unpreparable > 0)
                    throw new InvalidOperationException($"Cannot enable enforcement: {prep.Unpreparable} learned application(s) could not be converted into safe authorization candidates.");

                var paths = learned.Select(x => x.FilePath ?? string.Empty)
                    .Where(x => !string.IsNullOrWhiteSpace(x) && !LearnedPathClassifier.IsExpectedDotNetExtraction(x))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var requiredKeys = _backgroundStore.LearningRuleKeysForPaths(paths);
                var rules = _backgroundStore.RulesForKeys(requiredKeys).ToDictionary(x => x.CacheKey, StringComparer.OrdinalIgnoreCase);
                var unprepared = 0;
                foreach (var key in requiredKeys)
                {
                    if (!rules.TryGetValue(key, out var rule)) { unprepared++; continue; }
                    if (rule.Status == BackgroundPolicyStatuses.Ready && !string.IsNullOrWhiteSpace(rule.FragmentXmlPath) && File.Exists(rule.FragmentXmlPath))
                        continue;
                    try
                    {
                        var fragment = await GenerateRuleFragmentCoreAsync(rule, ct);
                        _backgroundStore.MarkRuleReady(rule.CacheKey, fragment.FragmentXmlPath, rule.MinimumFileVersion);
                    }
                    catch (Exception ex)
                    {
                        _backgroundStore.MarkRuleFailed(rule.CacheKey, ex.Message);
                        _log.Write($"learned-final-delta failed key={rule.CacheKey}: {ex.Message}");
                        unprepared++;
                    }
                }

                var ready = _backgroundStore.RulesForKeys(requiredKeys)
                    .Where(x => x.Status == BackgroundPolicyStatuses.Ready && !string.IsNullOrWhiteSpace(x.FragmentXmlPath) && File.Exists(x.FragmentXmlPath))
                    .ToArray();
                var prepared = ready.Length;
                if (prepared != requiredKeys.Count) unprepared += Math.Max(0, requiredKeys.Count - prepared - unprepared);
                finalDeltaTimer.Stop();
                _log.Write($"policy-helper ACM_STAGE learned-final-delta elapsed={finalDeltaTimer.Elapsed.TotalSeconds:F1}s learned={learned.Count} prepared={prepared} ignoredEphemeral={prep.IgnoredEphemeral} unprepared={unprepared}");
                if (unprepared > 0)
                    throw new InvalidOperationException($"Cannot enable enforcement: {unprepared} learned authorization fragment(s) remain unresolved.");
                if (learned.Count > 0 && prepared == 0 && prep.IgnoredEphemeral > 0)
                    throw new InvalidOperationException($"Learning observed {prep.IgnoredEphemeral} expected .NET extraction file(s), but none could be converted into safe authorization rules.");

                var FragmentListPath = Path.Combine(Path.GetTempPath(), $"AppControlManager-LearnedFragments-{Guid.NewGuid():N}.json");
                try
                {
                    var fragments = ready.Select(x => x.FragmentXmlPath!).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                    await File.WriteAllTextAsync(FragmentListPath, JsonSerializer.Serialize(fragments), new UTF8Encoding(false), ct);
                    var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "End-LearningAndEnforce.ps1");
                    var args = $"-NoTaskControl -FragmentListPath {Quote(FragmentListPath)} -LearnedCount {learned.Count} -PreparedCount {prepared} -UnpreparedCount {unprepared}";
                    await RunPowerShellAsync(script, args, ct);
                }
                finally { try { File.Delete(FragmentListPath); } catch { } }
            }
            finally { _policyGenerationGate.Release(); }
        }
        finally { Interlocked.Decrement(ref _foregroundWaiters); }
        _log.Write("enforcement-progress completed");
    }

    public async Task<InstallationFinalizationResult> FinalizeInstallationModeAsync(long installationId, CancellationToken ct)
    {
        _log.Write($"installation-finalize started id={installationId}");
        InstallationFinalizationResult? result = null;
        Interlocked.Increment(ref _foregroundWaiters);
        try
        {
            await _policyGenerationGate.WaitAsync(ct);
            try
            {
                var collectScript = Path.Combine(AppGuardPaths.ScriptsDirectory, "Get-LearnedApplications.ps1");
                await RunPowerShellAsync(collectScript, "-Save", ct);
                var learned = ReadLearnedApplications();
                var prep = _backgroundStore.PrepareLearningEvents(learned);

                var snapshot = _backgroundStore.Snapshot();
                var readyExistingRuleKeys = snapshot.Rules
                    .Where(x => x.Status == BackgroundPolicyStatuses.Ready && !string.IsNullOrWhiteSpace(x.FragmentXmlPath) && File.Exists(x.FragmentXmlPath))
                    .Select(x => x.CacheKey)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                var plan = InstallationLearningReconciler.Create(
                    learned.Select(x => new InstallationLearnedFile(x.FilePath, x.RecordId)),
                    prep.PreparedRuleKeysByPath,
                    snapshot.Learning,
                    readyExistingRuleKeys,
                    File.Exists,
                    LearnedPathClassifier.IsExpectedDotNetExtraction);
                var requiredKeys = plan.RequiredRuleKeys;
                var rules = _backgroundStore.RulesForKeys(requiredKeys).ToDictionary(x => x.CacheKey, StringComparer.OrdinalIgnoreCase);
                var unresolved = 0;
                foreach (var key in requiredKeys)
                {
                    if (!rules.TryGetValue(key, out var rule)) { unresolved++; continue; }
                    if (rule.Status == BackgroundPolicyStatuses.Ready && !string.IsNullOrWhiteSpace(rule.FragmentXmlPath) && File.Exists(rule.FragmentXmlPath)) continue;
                    try
                    {
                        var fragment = await GenerateRuleFragmentCoreAsync(rule, ct);
                        _backgroundStore.MarkRuleReady(rule.CacheKey, fragment.FragmentXmlPath, rule.MinimumFileVersion);
                    }
                    catch (Exception ex)
                    {
                        _backgroundStore.MarkRuleFailed(rule.CacheKey, ex.Message);
                        _log.Write($"installation-finalize fragment failed id={installationId} key={rule.CacheKey}: {ex.Message}");
                        unresolved++;
                    }
                }

                var ready = _backgroundStore.RulesForKeys(requiredKeys)
                    .Where(x => x.Status == BackgroundPolicyStatuses.Ready && !string.IsNullOrWhiteSpace(x.FragmentXmlPath) && File.Exists(x.FragmentXmlPath))
                    .ToArray();
                if (ready.Length != requiredKeys.Count) unresolved += Math.Max(0, requiredKeys.Count - ready.Length - unresolved);
                _log.Write($"installation-finalize delta id={installationId} learned={learned.Count} prepared={ready.Length} ignoredEphemeral={plan.IgnoredEphemeralCount} skipped={plan.SkippedCount} unresolved={unresolved}");
                if (unresolved > 0) throw new InvalidOperationException($"Installation Mode has {unresolved} unresolved learned authorization fragment(s).");
                if (learned.Count > 0 && ready.Length == 0 && (plan.SkippedCount + plan.IgnoredEphemeralCount) > 0)
                    throw new InvalidOperationException($"Installation Mode learned {plan.SkippedCount + plan.IgnoredEphemeralCount} file(s), but none could be converted into safe authorization rules.");

                if (ready.Length > 0)
                {
                    var listPath = Path.Combine(Path.GetTempPath(), $"AppControlManager-InstallationFragments-{Guid.NewGuid():N}.json");
                    try
                    {
                        var fragments = ready.Select(x => x.FragmentXmlPath!).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                        await File.WriteAllTextAsync(listPath, JsonSerializer.Serialize(fragments), new UTF8Encoding(false), ct);
                        var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "Install-MergedSupplemental.ps1");
                        var args = $"-FragmentListPath {Quote(listPath)} -Name {Quote("AppControl Manager Installation " + installationId)} -Json";
                        await RunPowerShellAsync(script, args, ct);
                    }
                    finally { try { File.Delete(listPath); } catch { } }
                }

                await ForceEnforcementCoreAsync(ct);
                result = new InstallationFinalizationResult
                {
                    LearnedCount = learned.Count,
                    InstalledRuleCount = ready.Length,
                    SkippedCount = plan.SkippedCount,
                    IgnoredEphemeralCount = plan.IgnoredEphemeralCount
                };
            }
            finally { _policyGenerationGate.Release(); }
        }
        finally { Interlocked.Decrement(ref _foregroundWaiters); }
        var completed = result ?? throw new InvalidOperationException("Installation Mode finalization did not produce a result.");
        _log.Write($"installation-finalize completed id={installationId} learned={completed.LearnedCount} installed={completed.InstalledRuleCount} ignoredEphemeral={completed.IgnoredEphemeralCount} skipped={completed.SkippedCount}");
        return completed;
    }

    public async Task ForceEnforcementAsync(CancellationToken ct)
    {
        await _policyGenerationGate.WaitAsync(ct);
        try { await ForceEnforcementCoreAsync(ct); }
        finally { _policyGenerationGate.Release(); }
    }

    private async Task ForceEnforcementCoreAsync(CancellationToken ct)
    {
        var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "Force-Enforcement.ps1");
        await RunPowerShellAsync(script, "-NoTaskControl", ct);
    }

    private List<EventUpload> ReadLearnedApplications()
    {
        if (!File.Exists(AppGuardPaths.LearnedApplicationsPath)) return [];
        using var document = JsonDocument.Parse(File.ReadAllText(AppGuardPaths.LearnedApplicationsPath, Encoding.UTF8));
        IEnumerable<JsonElement> items = document.RootElement.ValueKind == JsonValueKind.Array
            ? document.RootElement.EnumerateArray()
            : document.RootElement.ValueKind == JsonValueKind.Object ? new[] { document.RootElement } : Array.Empty<JsonElement>();
        var result = new List<EventUpload>();
        foreach (var item in items)
        {
            string? StringValue(string name) => item.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null ? value.ToString() : null;
            long? recordId = item.TryGetProperty("record_id", out var rid) && rid.TryGetInt64(out var n) ? n : null;
            result.Add(new EventUpload
            {
                EventId = 3076,
                RecordId = recordId,
                FilePath = StringValue("file_path"),
                Sha256 = StringValue("sha256"),
                Publisher = StringValue("publisher"),
                ProductName = StringValue("product_name"),
                FileVersion = StringValue("file_version")
            });
        }
        return result;
    }

    private async Task<string> RunPowerShellAsync(string script, string args, CancellationToken ct)
    {
        if (!File.Exists(script)) throw new FileNotFoundException("Required AppControl Manager policy helper is missing.", script);
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {Quote(script)} {args}",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start PowerShell policy helper.");
        var stdout = new StringBuilder();
        var stderrTask = p.StandardError.ReadToEndAsync(ct);
        while (true)
        {
            var line = await p.StandardOutput.ReadLineAsync(ct);
            if (line is null) break;
            if (IsPolicyHelperNoise(line)) continue;
            stdout.AppendLine(line);
            if (line.StartsWith("ACM_STAGE", StringComparison.OrdinalIgnoreCase))
                _log.Write("policy-helper " + line);
        }
        await p.WaitForExitAsync(ct);
        var stderr = CleanPolicyHelperOutput(await stderrTask);
        var stdoutText = stdout.ToString();
        if (p.ExitCode != 0) throw new InvalidOperationException($"Policy helper failed ({p.ExitCode}): {stderr}\n{stdoutText}".Trim());
        if (!string.IsNullOrWhiteSpace(stderr)) _log.Write("policy-helper stderr: " + stderr.Trim());
        return stdoutText;
    }

    private async Task<string> RunPowerShellCommandAsync(string command, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command {Quote(command)}",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start PowerShell policy helper.");
        var stdoutTask = p.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        var stdout = CleanPolicyHelperOutput(await stdoutTask);
        var stderr = CleanPolicyHelperOutput(await stderrTask);
        if (p.ExitCode != 0) throw new InvalidOperationException($"Policy helper failed ({p.ExitCode}): {stderr}\n{stdout}".Trim());
        if (!string.IsNullOrWhiteSpace(stderr)) _log.Write("policy-helper stderr: " + stderr.Trim());
        return stdout;
    }

    private static bool IsPolicyHelperNoise(string? line)
    {
        var normalized = line?.Trim().Trim('"');
        return string.Equals(normalized, "Scan completed successfully", StringComparison.OrdinalIgnoreCase);
    }

    private static string CleanPolicyHelperOutput(string output)
        => string.Join(Environment.NewLine, output.Split(['\r','\n'], StringSplitOptions.RemoveEmptyEntries).Where(line => !IsPolicyHelperNoise(line)));

    private sealed record ProcessResult(int ExitCode, string Stdout, string Stderr);

    private static async Task<ProcessResult> RunProcessAsync(string fileName, string arguments, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {fileName}.");
        var stdoutTask = p.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        return new ProcessResult(p.ExitCode, await stdoutTask, await stderrTask);
    }

    private static string SingleQuote(string value) => "'" + value.Replace("'", "''") + "'";
    private static string Quote(string value) => "\"" + value.Replace("\"", "`\"") + "\"";
}
