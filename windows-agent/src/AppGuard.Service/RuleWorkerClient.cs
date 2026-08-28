using System.Text;
using System.Text.Json;
using AppGuard.Core;

namespace AppGuard.Service;

public sealed class RuleWorkerClient
{
    private readonly FileLogger _log;
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };

    public RuleWorkerClient(FileLogger log) => _log = log;

    public async Task<BackgroundRuleFragmentResult> GenerateAsync(string kind, string sourcePath, string canonicalOutputPath, CancellationToken ct)
    {
        if (!kind.Equals("product", StringComparison.OrdinalIgnoreCase) && !kind.Equals("hash", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Rule worker kind must be product or hash.");
        if (!File.Exists(sourcePath)) throw new FileNotFoundException("Rule-worker source file is no longer available.", sourcePath);

        Directory.CreateDirectory(AppGuardPaths.RuleWorkerJobsDirectory);
        Directory.CreateDirectory(AppGuardPaths.RuleFragmentDirectory);
        var canonicalRoot = Path.GetFullPath(AppGuardPaths.RuleFragmentDirectory) + Path.DirectorySeparatorChar;
        var canonical = Path.GetFullPath(canonicalOutputPath);
        if (!canonical.StartsWith(canonicalRoot, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Rule-worker canonical output escaped the fragment cache directory.");

        var jobId = Guid.NewGuid().ToString("N");
        var jobDirectory = Path.Combine(AppGuardPaths.RuleWorkerJobsDirectory, jobId);
        Directory.CreateDirectory(jobDirectory);
        var extension = SafeExtension(sourcePath);
        var inputFileName = "input" + extension;
        var stagedInput = Path.Combine(jobDirectory, inputFileName);
        var requestPath = Path.Combine(jobDirectory, "request.json");
        var resultPath = Path.Combine(jobDirectory, "result.json");
        var workerFragment = Path.Combine(jobDirectory, "fragment.xml");
        var consumed = false;
        var deadline = DateTimeOffset.UtcNow.AddMinutes(35);

        try
        {
            File.Copy(sourcePath, stagedInput, true);
            var request = new RuleWorkerRequest { JobId = jobId, Kind = kind.ToLowerInvariant(), InputFileName = inputFileName };
            await WriteJsonAtomicAsync(requestPath, request, ct);
            _log.Write($"rule-worker queued id={jobId} kind={request.Kind} source={sourcePath}");

            while (!File.Exists(resultPath))
            {
                ct.ThrowIfCancellationRequested();
                if (DateTimeOffset.UtcNow >= deadline)
                    throw new TimeoutException("Rule worker did not return a result within 35 minutes.");
                await Task.Delay(TimeSpan.FromMilliseconds(250), ct);
            }

            RuleWorkerResult result;
            try
            {
                result = JsonSerializer.Deserialize<RuleWorkerResult>(await File.ReadAllTextAsync(resultPath, ct), Json)
                         ?? throw new InvalidDataException("Rule worker result was empty.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Rule worker returned invalid JSON.", ex);
            }
            consumed = true;
            if (!result.Success)
                throw new InvalidOperationException("Rule worker failed: " + (result.Error ?? "unknown error"));
            if (result.RuleCount <= 0)
                throw new InvalidOperationException("Rule worker reported success without any generated rules.");
            if (!File.Exists(workerFragment))
                throw new InvalidOperationException("Rule worker reported success without producing fragment.xml.");

            File.Copy(workerFragment, canonical, true);
            _log.Write($"rule-worker completed id={jobId} kind={result.Kind} rules={result.RuleCount} elapsed={result.ElapsedSeconds:F1}s");
            return new BackgroundRuleFragmentResult
            {
                FragmentXmlPath = canonical,
                RuleCount = result.RuleCount,
                Kind = string.IsNullOrWhiteSpace(result.Kind) ? request.Kind : result.Kind,
                ElapsedSeconds = result.ElapsedSeconds
            };
        }
        finally
        {
            if (consumed)
            {
                try { Directory.Delete(jobDirectory, true); } catch { }
            }
        }
    }

    private static string SafeExtension(string path)
    {
        var extension = Path.GetExtension(path);
        if (string.IsNullOrWhiteSpace(extension) || extension.Length > 16) return ".bin";
        return extension.Skip(1).All(c => char.IsLetterOrDigit(c)) ? extension : ".bin";
    }

    private static async Task WriteJsonAtomicAsync(string path, object value, CancellationToken ct)
    {
        var temp = path + ".tmp." + Guid.NewGuid().ToString("N");
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(value, Json), new UTF8Encoding(false), ct);
        File.Move(temp, path, true);
    }
}
