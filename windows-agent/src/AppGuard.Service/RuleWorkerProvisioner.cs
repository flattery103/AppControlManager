using System.Diagnostics;
using AppGuard.Core;

namespace AppGuard.Service;

internal static class RuleWorkerProvisioner
{
    internal const string ServiceName = "AppControlManagerRuleWorker";
    private const string DisplayName = "AppControl Manager Rule Worker";
    private const string LocalServiceAccount = @"NT AUTHORITY\LocalService";

    public static void EnsureInstalled()
    {
        Directory.CreateDirectory(AppGuardPaths.RuleWorkerDirectory);
        RunRequired("icacls.exe", AppGuardPaths.RuleWorkerDirectory, "/inheritance:r");
        RunRequired("icacls.exe", AppGuardPaths.RuleWorkerDirectory, "/grant:r", "*S-1-5-18:(OI)(CI)(F)");
        RunRequired("icacls.exe", AppGuardPaths.RuleWorkerDirectory, "/grant:r", "*S-1-5-32-544:(OI)(CI)(F)");
        RunRequired("icacls.exe", AppGuardPaths.RuleWorkerDirectory, "/grant:r", "*S-1-5-19:(OI)(CI)(M)");
        Directory.CreateDirectory(AppGuardPaths.RuleWorkerJobsDirectory);

        var executable = Path.Combine(AppGuardPaths.ProgramFilesRoot, "AppControlManager.Service.exe");
        var binPath = $"\"{executable}\" --rule-worker";
        var query = Run("sc.exe", "query", ServiceName);
        if (query.ExitCode != 0)
        {
            RunRequired("sc.exe", "create", ServiceName, "binPath=", binPath, "start=", "auto", "obj=", LocalServiceAccount, "DisplayName=", DisplayName);
        }
        else
        {
            RunRequired("sc.exe", "config", ServiceName, "binPath=", binPath, "start=", "auto", "obj=", LocalServiceAccount, "DisplayName=", DisplayName);
        }
        _ = Run("sc.exe", "description", ServiceName, "AppControl Manager generation-only ConfigCI worker running as Local Service");
        var after = Run("sc.exe", "query", ServiceName);
        if (!after.Stdout.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
        {
            var start = Run("sc.exe", "start", ServiceName);
            if (start.ExitCode != 0 && !start.Stdout.Contains("1056", StringComparison.OrdinalIgnoreCase) && !start.Stderr.Contains("1056", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"Could not start {ServiceName}: {start.Stderr} {start.Stdout}".Trim());
        }
    }

    private static void RunRequired(string fileName, params string[] args)
    {
        var result = Run(fileName, args);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"{fileName} failed ({result.ExitCode}): {result.Stderr} {result.Stdout}".Trim());
    }

    private static ProcessResult Run(string fileName, params string[] args)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var arg in args) process.StartInfo.ArgumentList.Add(arg);
        if (!process.Start()) return new ProcessResult(-1, "", "process did not start");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new ProcessResult(process.ExitCode, stdout, stderr);
    }

    private sealed record ProcessResult(int ExitCode, string Stdout, string Stderr);
}
