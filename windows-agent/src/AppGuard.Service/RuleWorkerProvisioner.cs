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
        RejectExistingReparsePoint(AppGuardPaths.RuleWorkerDirectory, "root directory");
        Directory.CreateDirectory(AppGuardPaths.RuleWorkerDirectory);
        RejectExistingReparsePoint(AppGuardPaths.RuleWorkerDirectory, "root directory");
        RunRequired("icacls.exe", AppGuardPaths.RuleWorkerDirectory, "/inheritance:r");
        RunRequired("icacls.exe", AppGuardPaths.RuleWorkerDirectory, "/grant:r", "*S-1-5-18:(OI)(CI)(F)");
        RunRequired("icacls.exe", AppGuardPaths.RuleWorkerDirectory, "/grant:r", "*S-1-5-32-544:(OI)(CI)(F)");
        RunRequired("icacls.exe", AppGuardPaths.RuleWorkerDirectory, "/grant:r", "*S-1-5-19:(OI)(CI)(RX)");

        RejectExistingReparsePoint(AppGuardPaths.RuleWorkerJobsDirectory, "jobs directory");
        Directory.CreateDirectory(AppGuardPaths.RuleWorkerJobsDirectory);
        RejectExistingReparsePoint(AppGuardPaths.RuleWorkerJobsDirectory, "jobs directory");
        RejectExistingReparsePoint(AppGuardPaths.RuleWorkerLog, "log file");
        if (!File.Exists(AppGuardPaths.RuleWorkerLog)) File.WriteAllText(AppGuardPaths.RuleWorkerLog, "");
        RejectExistingReparsePoint(AppGuardPaths.RuleWorkerLog, "log file");
        RunRequired("icacls.exe", AppGuardPaths.RuleWorkerLog, "/grant:r", "*S-1-5-19:(M)");

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

    internal static void EnsureRunning()
    {
        var state = Run("sc.exe", "query", ServiceName);
        if (state.ExitCode != 0)
            throw new InvalidOperationException($"Rule Worker service is unavailable: {state.Stderr} {state.Stdout}".Trim());
        if (state.Stdout.Contains("RUNNING", StringComparison.OrdinalIgnoreCase)) return;
        var start = Run("sc.exe", "start", ServiceName);
        if (start.ExitCode != 0 &&
            !start.Stdout.Contains("1056", StringComparison.OrdinalIgnoreCase) &&
            !start.Stderr.Contains("1056", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Rule Worker service stopped and could not be restarted: {start.Stderr} {start.Stdout}".Trim());
    }

    internal static void GrantJobAccess(string jobDirectory, string stagedInput, string requestPath)
    {
        var jobsRoot = Path.GetFullPath(AppGuardPaths.RuleWorkerJobsDirectory) + Path.DirectorySeparatorChar;
        var canonicalJob = Path.GetFullPath(jobDirectory);
        var directoryName = Path.GetFileName(Path.TrimEndingDirectorySeparator(canonicalJob));
        if (!canonicalJob.StartsWith(jobsRoot, StringComparison.OrdinalIgnoreCase) ||
            !Guid.TryParseExact(directoryName, "N", out _) ||
            (File.GetAttributes(canonicalJob) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Rule-worker job access target is invalid.");
        ProtectStagedFile(canonicalJob, stagedInput);
        ProtectStagedFile(canonicalJob, requestPath);

        RunRequired("icacls.exe", canonicalJob, "/inheritance:r");
        RunRequired("icacls.exe", canonicalJob, "/grant:r", "*S-1-5-18:(OI)(CI)(F)");
        RunRequired("icacls.exe", canonicalJob, "/grant:r", "*S-1-5-32-544:(OI)(CI)(F)");
        // Local Service can traverse the job and create outputs, but cannot delete or replace
        // the job directory. Files it creates inherit Modify so atomic result publication works.
        RunRequired("icacls.exe", canonicalJob, "/grant:r", "*S-1-5-19:(RD,WD,AD,REA,WEA,X,RA,WA,RC,S)");
        RunRequired("icacls.exe", canonicalJob, "/grant", "*S-1-5-19:(OI)(CI)(IO)(M)");
    }

    private static void ProtectStagedFile(string canonicalJob, string path)
    {
        var jobRoot = canonicalJob + Path.DirectorySeparatorChar;
        var canonical = Path.GetFullPath(path);
        if (!canonical.StartsWith(jobRoot, StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(canonical) ||
            (File.GetAttributes(canonical) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Rule-worker staged file target is invalid.");
        RunRequired("icacls.exe", canonical, "/inheritance:r");
        RunRequired("icacls.exe", canonical, "/grant:r", "*S-1-5-18:(F)");
        RunRequired("icacls.exe", canonical, "/grant:r", "*S-1-5-32-544:(F)");
        RunRequired("icacls.exe", canonical, "/grant:r", "*S-1-5-19:(R)");
    }

    private static void RejectExistingReparsePoint(string path, string description)
    {
        if (ReadLinkTarget(new FileInfo(path)) is not null || ReadLinkTarget(new DirectoryInfo(path)) is not null)
            throw new InvalidOperationException($"Rule-worker {description} cannot be a reparse point.");
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException($"Rule-worker {description} cannot be a reparse point.");
        }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { }
    }

    private static string? ReadLinkTarget(FileSystemInfo info)
    {
        try { return info.LinkTarget; }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
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
