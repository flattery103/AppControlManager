using System.Diagnostics;
using System.Text;
using System.Text.Json;
using AppGuard.Core;
using Microsoft.Extensions.Hosting;

namespace AppGuard.Service;

internal sealed class RuleWorkerService : BackgroundService
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(AppGuardPaths.RuleWorkerDirectory);
        Directory.CreateDirectory(AppGuardPaths.RuleWorkerJobsDirectory);
        WriteLog("rule-worker start");
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
                    await ProcessJobAsync(jobDirectory, requestPath, resultPath, stoppingToken);
                }
                await Task.Delay(TimeSpan.FromMilliseconds(250), stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { WriteLog("rule-worker stop"); }
    }

    private static async Task ProcessJobAsync(string jobDirectory, string requestPath, string resultPath, CancellationToken ct)
    {
        RuleWorkerResult result;
        try
        {
            var request = JsonSerializer.Deserialize<RuleWorkerRequest>(await File.ReadAllTextAsync(requestPath, ct), Json)
                          ?? throw new InvalidDataException("Rule worker request was empty.");
            ValidateRequest(jobDirectory, request);
            var inputPath = Path.Combine(jobDirectory, request.InputFileName);
            var fragmentPath = Path.Combine(jobDirectory, "fragment.xml");
            if (!File.Exists(inputPath)) throw new FileNotFoundException("Staged rule-worker input is missing.", inputPath);

            var script = Path.Combine(AppGuardPaths.ScriptsDirectory, "New-RuleFragment.ps1");
            if (!File.Exists(script)) throw new FileNotFoundException("Rule-fragment helper is missing.", script);
            WriteLog($"job start id={request.JobId} kind={request.Kind} file={request.InputFileName}");
            var output = await RunPowerShellAsync(script, request.Kind, inputPath, fragmentPath, ct);
            var jsonLine = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .LastOrDefault(x => x.TrimStart().StartsWith("{", StringComparison.Ordinal));
            if (jsonLine is null) throw new InvalidOperationException("Rule-fragment helper did not return JSON. Output: " + output);
            var fragment = JsonSerializer.Deserialize<WorkerFragmentOutput>(jsonLine, Json)
                           ?? throw new InvalidOperationException("Could not parse rule-fragment helper result.");
            if (fragment.RuleCount <= 0 || !File.Exists(fragmentPath))
                throw new InvalidOperationException("Rule-fragment helper did not produce a usable fragment.");
            result = new RuleWorkerResult
            {
                Success = true,
                RuleCount = fragment.RuleCount,
                Kind = request.Kind,
                ElapsedSeconds = fragment.ElapsedSeconds
            };
            WriteLog($"job success id={request.JobId} kind={request.Kind} rules={fragment.RuleCount} elapsed={fragment.ElapsedSeconds:F1}s");
        }
        catch (Exception ex)
        {
            result = new RuleWorkerResult { Success = false, Error = Limit(ex.Message, 8000) };
            WriteLog($"job failed dir={Path.GetFileName(jobDirectory)} error={Limit(ex.Message, 2000)}");
        }
        await WriteJsonAtomicAsync(resultPath, result, ct);
    }

    private static void ValidateRequest(string jobDirectory, RuleWorkerRequest request)
    {
        var directoryName = Path.GetFileName(Path.TrimEndingDirectorySeparator(jobDirectory));
        if (!Guid.TryParseExact(request.JobId, "N", out _) || !directoryName.Equals(request.JobId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Rule worker job ID is invalid.");
        if (!request.Kind.Equals("product", StringComparison.OrdinalIgnoreCase) && !request.Kind.Equals("hash", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Rule worker kind must be product or hash.");
        if (string.IsNullOrWhiteSpace(request.InputFileName) || request.InputFileName != Path.GetFileName(request.InputFileName))
            throw new InvalidDataException("Rule worker input filename is invalid.");
        var root = Path.GetFullPath(jobDirectory) + Path.DirectorySeparatorChar;
        var input = Path.GetFullPath(Path.Combine(jobDirectory, request.InputFileName));
        if (!input.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Rule worker input escaped the job directory.");
    }

    private static async Task<string> RunPowerShellAsync(string script, string kind, string inputPath, string fragmentPath, CancellationToken ct)
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
            WorkingDirectory = Path.GetDirectoryName(fragmentPath)!
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Kind", kind.ToLowerInvariant(), "-FilePath", inputPath, "-OutputPath", fragmentPath, "-Json" })
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

    private sealed class WorkerFragmentOutput
    {
        [System.Text.Json.Serialization.JsonPropertyName("rule_count")] public int RuleCount { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("elapsed_seconds")] public double ElapsedSeconds { get; set; }
    }
}
