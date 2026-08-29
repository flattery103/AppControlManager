using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AppGuard.Core;
using Microsoft.Extensions.Hosting;

namespace AppGuard.Service;

internal sealed class RuleWorkerService : BackgroundService
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(AppGuardPaths.RuleWorkerDirectory);
        Directory.CreateDirectory(AppGuardPaths.RuleWorkerJobsDirectory);
        WriteLog("rule-worker start");
        CleanupStaleJobs();
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                foreach (var jobDirectory in Directory.EnumerateDirectories(AppGuardPaths.RuleWorkerJobsDirectory).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                {
                    if (stoppingToken.IsCancellationRequested) break;
                    var requestPath = Path.Combine(jobDirectory, "request.json");
                    var resultPath = Path.Combine(jobDirectory, "result.json");
                    if (!File.Exists(requestPath) || File.Exists(resultPath)) continue;
                    await ProcessJobSafelyAsync(jobDirectory, requestPath, resultPath, stoppingToken);
                }
                await Task.Delay(TimeSpan.FromMilliseconds(250), stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { WriteLog("rule-worker stop"); }
    }

    private static async Task ProcessJobSafelyAsync(string jobDirectory, string requestPath, string resultPath, CancellationToken ct)
    {
        try { await ProcessJobAsync(jobDirectory, requestPath, resultPath, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            WriteLog($"job result publication failed dir={Path.GetFileName(jobDirectory)} error={SanitizeError(ex.Message, jobDirectory, 2000)}");
            try
            {
                var failed = new RuleWorkerResult { Success = false, Error = SanitizeError(ex.Message, jobDirectory, 8000) };
                await WriteJsonAtomicAsync(resultPath, failed, ct);
            }
            catch (Exception resultEx)
            {
                WriteLog($"job failure result unavailable dir={Path.GetFileName(jobDirectory)} error={SanitizeError(resultEx.Message, jobDirectory, 2000)}");
            }
        }
    }

    private static void CleanupStaleJobs()
    {
        var cutoff = DateTime.UtcNow.Subtract(TimeSpan.FromDays(7));
        foreach (var jobDirectory in Directory.EnumerateDirectories(AppGuardPaths.RuleWorkerJobsDirectory))
        {
            try
            {
                if ((File.GetAttributes(jobDirectory) & FileAttributes.ReparsePoint) != 0) continue;
                var newest = Directory.GetLastWriteTimeUtc(jobDirectory);
                foreach (var file in Directory.EnumerateFiles(jobDirectory, "*", SearchOption.TopDirectoryOnly))
                    newest = new[] { newest, File.GetLastWriteTimeUtc(file) }.Max();
                if (newest >= cutoff) continue;

                var requestPath = Path.Combine(jobDirectory, "request.json");
                var resultPath = Path.Combine(jobDirectory, "result.json");
                var abandonedUnpublished = !File.Exists(requestPath) && !File.Exists(resultPath);
                var completedFailed = false;
                if (File.Exists(resultPath))
                {
                    var result = JsonSerializer.Deserialize<RuleWorkerResult>(File.ReadAllText(resultPath), Json);
                    completedFailed = result is not null && !result.Success;
                }
                if (!abandonedUnpublished && !completedFailed) continue;
                Directory.Delete(jobDirectory, true);
                WriteLog($"stale job removed id={Path.GetFileName(jobDirectory)} failed={completedFailed}");
            }
            catch (Exception ex)
            {
                WriteLog($"stale job cleanup failed id={Path.GetFileName(jobDirectory)} error={Limit(ex.Message, 1000)}");
            }
        }
    }

    private static async Task ProcessJobAsync(string jobDirectory, string requestPath, string resultPath, CancellationToken ct)
    {
        RuleWorkerResult result;
        var operation = "";
        try
        {
            var request = JsonSerializer.Deserialize<RuleWorkerRequest>(await File.ReadAllTextAsync(requestPath, ct), Json)
                          ?? throw new InvalidDataException("Rule worker request was empty.");
            ValidateRequest(jobDirectory, request);
            operation = request.Operation.ToLowerInvariant();
            if (!RuleWorkerOperations.TryGetOutputFile(operation, out var outputFileName))
                throw new InvalidDataException("Rule worker operation is not allowed.");
            var inputPath = Path.GetFullPath(Path.Combine(jobDirectory, request.InputFileName));
            var outputPath = Path.GetFullPath(Path.Combine(jobDirectory, outputFileName));
            if (!File.Exists(inputPath)) throw new FileNotFoundException("Staged rule-worker input is missing.", inputPath);
            RejectReparsePoint(inputPath, "input");

            var scriptName = RuleWorkerOperations.IsFragmentOperation(operation) ? "New-RuleFragment.ps1" : "New-WorkerPolicy.ps1";
            var script = Path.Combine(AppGuardPaths.ScriptsDirectory, scriptName);
            if (!File.Exists(script)) throw new FileNotFoundException("Rule-generation helper is missing.", script);
            WriteLog($"job start id={request.JobId} operation={operation} file={request.InputFileName}");
            var output = await RunPowerShellAsync(script, operation, inputPath, outputPath, ct);
            var jsonLine = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .LastOrDefault(x => x.TrimStart().StartsWith("{", StringComparison.Ordinal));
            if (jsonLine is null) throw new InvalidOperationException("Rule-generation helper did not return JSON. Output: " + output);
            var generated = JsonSerializer.Deserialize<WorkerGenerationOutput>(jsonLine, Json)
                            ?? throw new InvalidOperationException("Could not parse rule-generation helper result.");
            if (!generated.Operation.Equals(operation, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Rule-generation helper returned a different operation.");
            if (generated.RuleCount <= 0 || string.IsNullOrWhiteSpace(generated.RuleMode) || !File.Exists(outputPath))
                throw new InvalidOperationException("Rule-generation helper did not produce usable policy XML.");
            RejectReparsePoint(outputPath, "output");
            result = new RuleWorkerResult
            {
                Success = true,
                Operation = operation,
                RuleCount = generated.RuleCount,
                RuleMode = generated.RuleMode,
                ElapsedSeconds = generated.ElapsedSeconds,
                FilePath = generated.FilePath,
                Sha256 = generated.Sha256,
                Publisher = generated.Publisher,
                ProductName = generated.ProductName,
                FileVersion = generated.FileVersion
            };
            WriteLog($"job success id={request.JobId} operation={operation} mode={generated.RuleMode} rules={generated.RuleCount} elapsed={generated.ElapsedSeconds:F1}s");
        }
        catch (Exception ex)
        {
            var error = SanitizeError(ex.Message, jobDirectory, 8000);
            result = new RuleWorkerResult { Success = false, Operation = operation, Error = error };
            WriteLog($"job failed dir={Path.GetFileName(jobDirectory)} error={SanitizeError(ex.Message, jobDirectory, 2000)}");
        }
        await WriteJsonAtomicAsync(resultPath, result, ct);
    }

    private static void ValidateRequest(string jobDirectory, RuleWorkerRequest request)
    {
        RejectReparsePoint(jobDirectory, "job directory");
        var directoryName = Path.GetFileName(Path.TrimEndingDirectorySeparator(jobDirectory));
        if (!Guid.TryParseExact(request.JobId, "N", out _) || !directoryName.Equals(request.JobId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Rule worker job ID is invalid.");
        if (!RuleWorkerOperations.TryGetOutputFile(request.Operation, out _))
            throw new InvalidDataException("Rule worker operation is not allowed.");
        if (string.IsNullOrWhiteSpace(request.InputFileName) || request.InputFileName != Path.GetFileName(request.InputFileName))
            throw new InvalidDataException("Rule worker input filename is invalid.");
        var root = Path.GetFullPath(jobDirectory) + Path.DirectorySeparatorChar;
        var input = Path.GetFullPath(Path.Combine(jobDirectory, request.InputFileName));
        if (!input.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Rule worker input escaped the job directory.");
    }

    private static void RejectReparsePoint(string path, string description)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException($"Rule worker {description} cannot be a reparse point.");
    }

    private static async Task<string> RunPowerShellAsync(string script, string operation, string inputPath, string outputPath, CancellationToken ct)
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var powershell = Path.Combine(system, "WindowsPowerShell", "v1.0", "powershell.exe");
        var startInfo = new ProcessStartInfo
        {
            FileName = powershell,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(outputPath)!
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Operation", operation, "-FilePath", inputPath, "-OutputPath", outputPath, "-Json" })
            startInfo.ArgumentList.Add(argument);
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start Local Service rule-generation PowerShell process.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync(ct); }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(true); } catch { }
            throw;
        }
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"Policy helper failed ({process.ExitCode}): {Limit(CleanOutput(stderr + Environment.NewLine + stdout), 8000)}");
        return CleanOutput(stdout);
    }

    private static string CleanOutput(string value)
        => string.Join(Environment.NewLine, value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Where(x => !x.Trim().Equals("\"Scan completed successfully\"", StringComparison.OrdinalIgnoreCase) &&
                        !x.Trim().Equals("Scan completed successfully", StringComparison.OrdinalIgnoreCase)));

    private static async Task WriteJsonAtomicAsync(string path, object value, CancellationToken ct)
    {
        var temp = path + ".tmp." + Guid.NewGuid().ToString("N");
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(value, Json), new UTF8Encoding(false), ct);
        File.Move(temp, path, true);
    }

    private static void WriteLog(string message)
    {
        try
        {
            Directory.CreateDirectory(AppGuardPaths.RuleWorkerDirectory);
            File.AppendAllText(AppGuardPaths.RuleWorkerLog, $"{DateTimeOffset.Now:O} {message}{Environment.NewLine}", new UTF8Encoding(false));
        }
        catch { }
    }

    private static string Limit(string value, int max) => value.Length <= max ? value : value[..max];

    private static string SanitizeError(string value, string jobDirectory, int max)
    {
        var sanitized = CleanOutput(value).Replace(jobDirectory, "[job]", StringComparison.OrdinalIgnoreCase);
        sanitized = new string(sanitized.Where(c => !char.IsControl(c) || c is '\r' or '\n' or '\t').ToArray()).Trim();
        return Limit(sanitized, max);
    }

    private sealed class WorkerGenerationOutput
    {
        [System.Text.Json.Serialization.JsonPropertyName("operation")] public string Operation { get; set; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("rule_count")] public int RuleCount { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("rule_mode")] public string RuleMode { get; set; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("elapsed_seconds")] public double ElapsedSeconds { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("file_path")] public string? FilePath { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("sha256")] public string? Sha256 { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("publisher")] public string? Publisher { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("product_name")] public string? ProductName { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("file_version")] public string? FileVersion { get; set; }
    }
}
