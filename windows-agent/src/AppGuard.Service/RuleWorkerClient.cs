using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AppGuard.Core;

namespace AppGuard.Service;

public sealed class RuleWorkerClient
{
    private static readonly TimeSpan WorkerResultTimeout = TimeSpan.FromMinutes(5);
    private readonly FileLogger _log;
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    public RuleWorkerClient(FileLogger log) => _log = log;

    public async Task<RuleWorkerResult> GenerateAsync(string operation, string sourcePath, string canonicalOutputPath, CancellationToken ct)
    {
        if (!RuleWorkerOperations.TryGetOutputFile(operation, out var workerOutputFileName))
            throw new InvalidOperationException("Rule worker operation is not allowed.");
        operation = operation.ToLowerInvariant();
        if (!File.Exists(sourcePath)) throw new FileNotFoundException("Rule-worker source file is no longer available.", sourcePath);

        RejectReparsePoint(AppGuardPaths.RuleWorkerDirectory, "root directory");
        RejectReparsePoint(AppGuardPaths.RuleWorkerJobsDirectory, "jobs directory");
        var canonicalDirectory = RuleWorkerOperations.IsFragmentOperation(operation)
            ? AppGuardPaths.RuleFragmentDirectory
            : AppGuardPaths.PolicyDirectory;
        RejectExistingReparsePoint(canonicalDirectory, "protected output directory");
        Directory.CreateDirectory(canonicalDirectory);
        RejectReparsePoint(canonicalDirectory, "protected output directory");
        var canonical = ValidateCanonicalOutput(canonicalDirectory, canonicalOutputPath);

        var jobId = Guid.NewGuid().ToString("N");
        var jobDirectory = Path.Combine(AppGuardPaths.RuleWorkerJobsDirectory, jobId);
        RejectReparsePoint(AppGuardPaths.RuleWorkerJobsDirectory, "jobs directory");
        Directory.CreateDirectory(jobDirectory);
        RejectReparsePoint(jobDirectory, "job directory");
        var extension = SafeExtension(sourcePath);
        var inputFileName = "input" + extension;
        var stagedInput = Path.Combine(jobDirectory, inputFileName);
        var requestPath = Path.Combine(jobDirectory, "request.json");
        var unpublishedRequestPath = Path.Combine(jobDirectory, "request.pending.json");
        var resultPath = Path.Combine(jobDirectory, "result.json");
        var workerOutput = Path.GetFullPath(Path.Combine(jobDirectory, workerOutputFileName));
        var jobRoot = Path.GetFullPath(jobDirectory) + Path.DirectorySeparatorChar;
        if (!workerOutput.StartsWith(jobRoot, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Fixed rule-worker output escaped the job directory.");
        var consumed = false;
        var publishedToWorker = false;
        var deadline = DateTimeOffset.UtcNow.Add(WorkerResultTimeout);
        var nextLivenessCheck = DateTimeOffset.MinValue;

        try
        {
            File.Copy(sourcePath, stagedInput, false);
            RejectReparsePoint(stagedInput, "staged input");
            var expectedIdentity = WorkerPolicyInputIdentity.FromFile(stagedInput);
            var request = new RuleWorkerRequest { JobId = jobId, Operation = operation, InputFileName = inputFileName };
            await WriteJsonAtomicAsync(unpublishedRequestPath, request, ct);
            RejectReparsePoint(unpublishedRequestPath, "unpublished request");
            RuleWorkerProvisioner.GrantJobAccess(jobDirectory, stagedInput, unpublishedRequestPath);
            File.Move(unpublishedRequestPath, requestPath, false);
            RejectReparsePoint(requestPath, "request");
            publishedToWorker = true;
            RuleWorkerProvisioner.EnsureRunning();
            _log.Write($"rule-worker queued id={jobId} operation={request.Operation} source={sourcePath}");

            while (!File.Exists(resultPath))
            {
                ct.ThrowIfCancellationRequested();
                if (DateTimeOffset.UtcNow >= deadline)
                    throw new TimeoutException("Rule worker did not return a result within 5 minutes.");
                if (DateTimeOffset.UtcNow >= nextLivenessCheck)
                {
                    RuleWorkerProvisioner.EnsureRunning();
                    nextLivenessCheck = DateTimeOffset.UtcNow.AddSeconds(5);
                }
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
            if (!result.Operation.Equals(request.Operation, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Rule worker returned a result for a different operation.");
            if (!result.Success)
                throw new InvalidOperationException("Rule worker failed: " + SanitizeError(result.Error));
            if (result.RuleCount <= 0)
                throw new InvalidOperationException("Rule worker reported success without any generated rules.");
            if (string.IsNullOrWhiteSpace(result.RuleMode))
                throw new InvalidOperationException("Rule worker reported success without a selected rule mode.");
            RejectReparsePoint(jobDirectory, "job directory");
            RejectReparsePoint(canonicalDirectory, "protected output directory");
            var protectedSnapshot = WorkerOutputSnapshot.CopyExactToProtected(workerOutput, workerOutput, canonicalDirectory);
            try
            {
                var validatedRuleMode = WorkerPolicyValidator.ValidateAndNormalizeFile(protectedSnapshot, operation, expectedIdentity);
                if (!result.RuleMode.Equals(validatedRuleMode, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Rule worker reported a rule mode that did not match its protected policy snapshot.");
                result.RuleMode = validatedRuleMode;
                File.Move(protectedSnapshot, canonical, true);
            }
            finally { try { File.Delete(protectedSnapshot); } catch { } }
            // Preserve the LocalSystem caller path and use only LocalSystem-computed
            // identity metadata; worker-returned file metadata is never authoritative.
            result.FilePath = sourcePath;
            result.Sha256 = expectedIdentity.ContentSha256;
            result.Publisher = expectedIdentity.Publisher;
            result.ProductName = expectedIdentity.ProductName;
            result.FileVersion = expectedIdentity.FileVersion;
            result.Error = null;
            _log.Write($"rule-worker completed id={jobId} operation={result.Operation} mode={result.RuleMode} rules={result.RuleCount} elapsed={result.ElapsedSeconds:F1}s");
            return result;
        }
        finally
        {
            if (consumed || !publishedToWorker)
            {
                try { Directory.Delete(jobDirectory, true); } catch { }
            }
        }
    }

    private static string ValidateCanonicalOutput(string canonicalDirectory, string canonicalOutputPath)
    {
        var canonicalRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(canonicalDirectory));
        var canonical = Path.GetFullPath(canonicalOutputPath);
        if (!string.Equals(Path.GetDirectoryName(canonical), canonicalRoot, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetExtension(canonical).Equals(".xml", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Rule-worker canonical output escaped its protected XML directory.");
        return canonical;
    }

    private static void RejectReparsePoint(string path, string description)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException($"Rule worker {description} cannot be a reparse point.");
    }

    private static void RejectExistingReparsePoint(string path, string description)
    {
        try { RejectReparsePoint(path, description); }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { }
    }

    private static string SanitizeError(string? error)
    {
        var value = string.IsNullOrWhiteSpace(error) ? "unknown error" : error;
        value = string.Join(" ", value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)).Trim();
        return value.Length <= 8000 ? value : value[..8000];
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
