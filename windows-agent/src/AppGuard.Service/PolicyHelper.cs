using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using System.Text;
using AppGuard.Core;

namespace AppGuard.Service;

public sealed class PolicyHelper
{
    private readonly FileLogger _log;
    private readonly PolicyProgressTracker _progress;
    private readonly ConcurrentDictionary<string, PublisherCacheEntry> _publisherCache = new(StringComparer.OrdinalIgnoreCase);
    private const int PublisherCacheLimit = 5000;
    public PolicyHelper(FileLogger log, PolicyProgressTracker progress)
    {
        _log = log;
        _progress = progress;
    }

    public Task<SupplementalResult> ApproveFileAsync(string filePath, long requestId, CancellationToken ct)
        => ApproveFilesAsync([filePath], requestId, ct);

    public async Task<SupplementalResult> ApproveFilesAsync(IReadOnlyList<string> filePaths, long requestId, CancellationToken ct)
    {
        var requested = filePaths.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (requested.Length == 0) throw new FileNotFoundException("None of the approved component files are available for policy generation.");

        _progress.Update(requestId, "scanning", "Scanning the installed application for related signed components...", requested.Length);

        // Discover protected-install application bundles in the C# service. This deliberately
        // uses the same PE certificate reader as normal AppGuard metadata collection, avoiding
        // differences we observed between service metadata and PowerShell Get-AuthenticodeSignature.
        var expansion = ExpandProtectedApplicationBundles(requested);
        var files = expansion.Files;
        var expanded = Math.Max(files.Length - requested.Length, 0);
        _log.Write($"bundle-scan summary requested={requested.Length} policyFiles={files.Length} expanded={expanded} roots={expansion.RootScans} duplicateRootsSkipped={expansion.DuplicateScansSkipped} filesExamined={expansion.FilesExamined} signerReads={expansion.SignerReads} cacheHits={expansion.CacheHits} scanElapsed={expansion.ScanElapsed.TotalSeconds:F2}s primary={requested[0]}");

        _progress.Update(requestId, "scanning", $"Application scan complete: examined {expansion.FilesExamined} executable file(s) across {expansion.RootScans} application root(s) in {expansion.ScanElapsed.TotalSeconds:F1}s; signer cache hits: {expansion.CacheHits}.", files.Length);
        _progress.Update(requestId, "building", $"Building and installing the Windows App Control policy for {files.Length} file(s)...", files.Length);
        var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "New-SupplementalForFiles.ps1");

        // Do not place an expanded application bundle on the powershell.exe command line.
        // Large signed application trees (for example the .NET runtime) can contain hundreds
        // of component paths and exceed Windows CreateProcess command-line limits. Pass the
        // list through a temporary JSON data file instead; PowerShell receives only the short
        // list-file path while policy coverage remains identical.
        var fileListPath = Path.Combine(Path.GetTempPath(), $"AppControlManager-PolicyFiles-{Guid.NewGuid():N}.json");
        string output;
        var started = DateTimeOffset.UtcNow;
        try
        {
            await File.WriteAllTextAsync(fileListPath, JsonSerializer.Serialize(files), new UTF8Encoding(false), ct);
            var args = $"-FileListPath {Quote(fileListPath)} -Name {Quote("AppControl Manager Approval " + requestId)} -Json -AlreadyExpanded";
            _log.Write($"policy-helper start request={requestId} files={files.Length} listFile={fileListPath}");
            output = await RunPowerShellAsync(script, args, ct);
        }
        finally
        {
            try { if (File.Exists(fileListPath)) File.Delete(fileListPath); } catch { }
        }
        _log.Write($"policy-helper finished request={requestId} files={files.Length} elapsed={(DateTimeOffset.UtcNow - started).TotalSeconds:F1}s");
        var line = output.Split(['\r','\n'], StringSplitOptions.RemoveEmptyEntries).LastOrDefault(x => x.TrimStart().StartsWith("{"));
        if (line is null) throw new InvalidOperationException("Policy helper did not return JSON. Output: " + output);
        var result = JsonSerializer.Deserialize<SupplementalResult>(line, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                     ?? throw new InvalidOperationException("Could not parse policy helper result.");
        _progress.Update(requestId, "installed", "The allow policy is installed. Finalizing approval status...", files.Length);

        // The PowerShell helper sees the already-expanded list as its input. Restore the semantic
        // counts so logs/server results describe how many files the user actually requested vs.
        // how many AppGuard added automatically.
        result.RequestedFiles = requested.Length;
        result.PolicyFiles = files.Length;
        result.ExpandedFiles = expanded;
        if (expanded > 0) result.RuleType = "FilePublisher Application Bundle";
        return result;
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
        return new BundleExpansionResult(output.ToArray(), filesExamined, signerReads, cacheHits, rootScans, duplicateScansSkipped, scanElapsed);
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
    private sealed record BundleExpansionResult(
        string[] Files,
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

    public async Task<SupplementalResult> BlockFileAsync(string filePath, long blockId, CancellationToken ct)
    {
        if (!File.Exists(filePath)) throw new FileNotFoundException("The file to block is no longer available for policy generation.", filePath);
        var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "New-DenyPolicyForFile.ps1");
        var command = $"& {{ & {SingleQuote(script)} -FilePath @({SingleQuote(filePath)}) -Name {SingleQuote("AppControl Manager Deny " + blockId)} -Json }}";
        var output = await RunPowerShellCommandAsync(command, ct);
        var line = output.Split(['\r','\n'], StringSplitOptions.RemoveEmptyEntries).LastOrDefault(x => x.TrimStart().StartsWith("{"));
        if (line is null) throw new InvalidOperationException("Deny policy helper did not return JSON. Output: " + output);
        return JsonSerializer.Deserialize<SupplementalResult>(line, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
               ?? throw new InvalidOperationException("Could not parse deny policy helper result.");
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
        var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "Start-LearningMode.ps1");
        await RunPowerShellAsync(script, "-NoTaskControl", ct);
    }

    public async Task EnableEnforcementAsync(CancellationToken ct)
    {
        var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "End-LearningAndEnforce.ps1");
        await RunPowerShellAsync(script, "-NoTaskControl", ct);
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
        var stdoutTask = p.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        if (p.ExitCode != 0) throw new InvalidOperationException($"Policy helper failed ({p.ExitCode}): {stderr}\n{stdout}".Trim());
        if (!string.IsNullOrWhiteSpace(stderr)) _log.Write("policy-helper stderr: " + stderr.Trim());
        return stdout;
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
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        if (p.ExitCode != 0) throw new InvalidOperationException($"Policy helper failed ({p.ExitCode}): {stderr}\n{stdout}".Trim());
        if (!string.IsNullOrWhiteSpace(stderr)) _log.Write("policy-helper stderr: " + stderr.Trim());
        return stdout;
    }

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
