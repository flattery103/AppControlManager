using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using AppGuard.Core;

namespace AppGuard.Service;

public sealed class AgentUpdater
{
    private readonly ApiClient _api;
    private readonly PolicyHelper _policies;
    private readonly FileLogger _log;
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };

    public AgentUpdater(ApiClient api, PolicyHelper policies, FileLogger log)
    {
        _api = api; _policies = policies; _log = log;
        Directory.CreateDirectory(AppGuardPaths.UpdateDirectory);
    }

    public sealed record StagedAgentUpdate(string TargetVersion, string StagingPath, string StatusPath);
    public sealed record HeartbeatUpdateStatus(string? Status, string? Result);

    private sealed class UpdateStatusFile
    {
        public string? status { get; set; }
        public string? target_version { get; set; }
        public string? from_version { get; set; }
        public string? result { get; set; }
        public string? staged_path { get; set; }
        public string? backup_path { get; set; }
        public string? preauth_policy_id { get; set; }
        public string? previous_preauth_policy_id { get; set; }
        public bool cleanup_complete { get; set; }
        public string? updated_at { get; set; }
    }

    private sealed class CurrentUpdateFile
    {
        public string? version { get; set; }
        public string? preauth_policy_id { get; set; }
    }

    public HeartbeatUpdateStatus GetHeartbeatStatus(string currentVersion)
    {
        var status = ReadStatus();
        if (status is null) return new HeartbeatUpdateStatus(null, null);
        if (string.Equals(status.status, "installed", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(status.target_version, currentVersion, StringComparison.OrdinalIgnoreCase))
            return new HeartbeatUpdateStatus("installing", "Update helper completed; waiting for the target agent version to report.");
        return new HeartbeatUpdateStatus(status.status, status.result);
    }

    public async Task<StagedAgentUpdate> StageAsync(long commandId, string targetVersion, string sha256, string downloadPath, string currentVersion, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(targetVersion)) throw new InvalidOperationException("Update target version was empty.");
        if (string.IsNullOrWhiteSpace(sha256)) throw new InvalidOperationException("Update package SHA256 was empty.");
        if (string.IsNullOrWhiteSpace(downloadPath)) throw new InvalidOperationException("Update package download path was empty.");

        var root = Path.Combine(AppGuardPaths.UpdateDirectory, targetVersion);
        var package = Path.Combine(root, "agent-package.zip");
        var staging = Path.Combine(root, "staging");
        if (Directory.Exists(root)) Directory.Delete(root, true);
        Directory.CreateDirectory(staging);

        WriteStatus(new UpdateStatusFile { status = "downloading", target_version = targetVersion, from_version = currentVersion, result = $"Downloading AppControl Manager agent {targetVersion}...", staged_path = staging, updated_at = DateTimeOffset.UtcNow.ToString("O") });
        _log.Write($"agent-update download start command={commandId} target={targetVersion}");
        await _api.DownloadFileAsync(downloadPath, package, ct);

        string actual;
        await using (var packageStream = File.OpenRead(package))
            actual = Convert.ToHexString(await SHA256.HashDataAsync(packageStream, ct));
        if (!actual.Equals(sha256.Replace("-", ""), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"Agent update SHA256 mismatch. Expected {sha256}; received {actual}.");

        WriteStatus(new UpdateStatusFile { status = "staging", target_version = targetVersion, from_version = currentVersion, result = "Package hash verified. Extracting update...", staged_path = staging, updated_at = DateTimeOffset.UtcNow.ToString("O") });
        ZipFile.ExtractToDirectory(package, staging, true);
        ValidateStaging(staging, targetVersion);

        string? newPolicy = null;
        var previousPolicy = ReadCurrent()?.preauth_policy_id;
        if (File.Exists(AppGuardPaths.BasePolicyXml))
        {
            WriteStatus(new UpdateStatusFile { status = "staging", target_version = targetVersion, from_version = currentVersion, result = "Pre-authorizing the replacement service and tray binaries with Windows App Control...", staged_path = staging, previous_preauth_policy_id = previousPolicy, updated_at = DateTimeOffset.UtcNow.ToString("O") });
            var service = Path.Combine(staging, "Service", "AppControlManager.Service.exe");
            var tray = Path.Combine(staging, "Tray", "AppControlManager.Tray.exe");
            var policy = await _policies.PreauthorizeAgentUpdateAsync([service, tray], -commandId, ct);
            newPolicy = policy.PolicyId;
            _log.Write($"agent-update preauthorized target={targetVersion} policy={newPolicy}");
        }

        var status = new UpdateStatusFile
        {
            status = "staged", target_version = targetVersion, from_version = currentVersion,
            result = $"Agent {targetVersion} verified and staged. Activation is starting.", staged_path = staging,
            preauth_policy_id = newPolicy, previous_preauth_policy_id = previousPolicy,
            updated_at = DateTimeOffset.UtcNow.ToString("O")
        };
        WriteStatus(status);
        return new StagedAgentUpdate(targetVersion, staging, AppGuardPaths.UpdateStatusPath);
    }

    public void LaunchActivation(StagedAgentUpdate update, string currentVersion)
    {
        var script = Path.Combine(update.StagingPath, "scripts", "Apply-AgentUpdate.ps1");
        if (!File.Exists(script)) throw new FileNotFoundException("Agent update activation helper is missing.", script);
        var backup = Path.Combine(AppGuardPaths.UpdateDirectory, "Backups");
        Directory.CreateDirectory(backup);
        var args = $"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {Quote(script)} -StagingPath {Quote(update.StagingPath)} -TargetVersion {Quote(update.TargetVersion)} -CurrentVersion {Quote(currentVersion)} -StatusPath {Quote(update.StatusPath)} -BackupRoot {Quote(backup)}";
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe", Arguments = args, UseShellExecute = false,
            CreateNoWindow = true, WorkingDirectory = AppGuardPaths.ProgramDataRoot
        };
        var activationProcess = Process.Start(psi);
        if (activationProcess is null)
            throw new InvalidOperationException("Could not start the AppControl Manager update activation helper.");
        activationProcess.Dispose();
        _log.Write($"agent-update activation launched target={update.TargetVersion}");
    }

    public async Task CleanupPreviousTrustAsync(string currentVersion, CancellationToken ct)
    {
        var status = ReadStatus();
        if (status is null || status.cleanup_complete) return;

        // Successful update: once the replacement agent itself has heartbeated, the old update-only
        // preauthorization can be removed. Keep the new preauthorization as the current updater trust.
        if (string.Equals(status.status, "installed", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(status.target_version, currentVersion, StringComparison.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(status.previous_preauth_policy_id) &&
                !string.Equals(status.previous_preauth_policy_id, status.preauth_policy_id, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    await _policies.RemovePolicyAsync(status.previous_preauth_policy_id, ct);
                    _log.Write($"agent-update removed previous preauthorization policy id={status.previous_preauth_policy_id}");
                }
                catch (Exception ex) { _log.Write("agent-update previous trust cleanup (will retry): " + ex.Message); return; }
            }
            WriteCurrent(new CurrentUpdateFile { version = currentVersion, preauth_policy_id = status.preauth_policy_id });
            status.cleanup_complete = true;
            status.updated_at = DateTimeOffset.UtcNow.ToString("O");
            WriteStatus(status);
            return;
        }

        // Failed/rolled-back update: remove the temporary authorization for binaries that were not
        // retained. This prevents a failed update package from remaining allowed indefinitely.
        if ((string.Equals(status.status, "rolled_back", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(status.status, "failed", StringComparison.OrdinalIgnoreCase)) &&
            string.Equals(status.from_version, currentVersion, StringComparison.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(status.preauth_policy_id) &&
                !string.Equals(status.preauth_policy_id, status.previous_preauth_policy_id, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    await _policies.RemovePolicyAsync(status.preauth_policy_id, ct);
                    _log.Write($"agent-update removed failed-update preauthorization policy id={status.preauth_policy_id}");
                }
                catch (Exception ex) { _log.Write("agent-update failed trust cleanup: " + ex.Message); return; }
            }
            WriteCurrent(new CurrentUpdateFile { version = currentVersion, preauth_policy_id = status.previous_preauth_policy_id });
            status.cleanup_complete = true;
            status.updated_at = DateTimeOffset.UtcNow.ToString("O");
            WriteStatus(status);
        }
    }

    private static void ValidateStaging(string staging, string expectedVersion)
    {
        var required = new[]
        {
            Path.Combine(staging, "Service", "AppControlManager.Service.exe"),
            Path.Combine(staging, "Tray", "AppControlManager.Tray.exe"),
            Path.Combine(staging, "scripts", "Apply-AgentUpdate.ps1"),
            Path.Combine(staging, "agent-manifest.json")
        };
        foreach (var file in required) if (!File.Exists(file)) throw new InvalidDataException("Agent package is missing " + file);
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(staging, "agent-manifest.json")));
        var version = doc.RootElement.TryGetProperty("version", out var v) ? v.GetString() : null;
        if (!string.Equals(version, expectedVersion, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"Agent package manifest version {version} does not match requested version {expectedVersion}.");

        if (!doc.RootElement.TryGetProperty("files", out var files) || files.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Agent package manifest does not contain a files list.");
        var manifestPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in files.EnumerateArray())
        {
            var relative = entry.TryGetProperty("path", out var p) ? p.GetString() : null;
            var expectedHash = entry.TryGetProperty("sha256", out var h) ? h.GetString() : null;
            if (string.IsNullOrWhiteSpace(relative) || string.IsNullOrWhiteSpace(expectedHash))
                throw new InvalidDataException("Agent package manifest contains an invalid file entry.");
            var manifestPath = relative.Replace('\\', '/');
            if (!manifestPaths.Add(manifestPath))
                throw new InvalidDataException("Agent package manifest contains a duplicate file entry: " + relative);
            var normalized = relative.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
            var full = Path.GetFullPath(Path.Combine(staging, normalized));
            var stageRoot = Path.GetFullPath(staging) + Path.DirectorySeparatorChar;
            if (!full.StartsWith(stageRoot, StringComparison.OrdinalIgnoreCase) || !File.Exists(full))
                throw new InvalidDataException("Agent package manifest references a missing or unsafe path: " + relative);
            using var stream = File.OpenRead(full);
            var actualHash = Convert.ToHexString(SHA256.HashData(stream));
            if (!actualHash.Equals(expectedHash.Replace("-", ""), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Agent package file hash mismatch: " + relative);
            if (entry.TryGetProperty("size", out var sizeElement) && sizeElement.TryGetInt64(out var expectedSize) && new FileInfo(full).Length != expectedSize)
                throw new InvalidDataException("Agent package file size mismatch: " + relative);
        }

        var requiredManifestPaths = new[]
        {
            "Service/AppControlManager.Service.exe",
            "Tray/AppControlManager.Tray.exe",
            "scripts/Apply-AgentUpdate.ps1"
        };
        foreach (var requiredPath in requiredManifestPaths)
            if (!manifestPaths.Contains(requiredPath))
                throw new InvalidDataException("Agent package manifest does not authenticate required file: " + requiredPath);

        foreach (var file in Directory.EnumerateFiles(staging, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(staging, file).Replace('\\', '/');
            if (relative.Equals("agent-manifest.json", StringComparison.OrdinalIgnoreCase)) continue;
            if (!manifestPaths.Contains(relative))
                throw new InvalidDataException("Agent package contains an unmanifested file: " + relative);
        }
    }

    private UpdateStatusFile? ReadStatus()
    {
        try { return File.Exists(AppGuardPaths.UpdateStatusPath) ? JsonSerializer.Deserialize<UpdateStatusFile>(File.ReadAllText(AppGuardPaths.UpdateStatusPath), Json) : null; }
        catch { return null; }
    }
    private CurrentUpdateFile? ReadCurrent()
    {
        try { return File.Exists(AppGuardPaths.UpdateCurrentPath) ? JsonSerializer.Deserialize<CurrentUpdateFile>(File.ReadAllText(AppGuardPaths.UpdateCurrentPath), Json) : null; }
        catch { return null; }
    }
    private static void WriteStatus(UpdateStatusFile status)
    {
        Directory.CreateDirectory(AppGuardPaths.UpdateDirectory);
        File.WriteAllText(AppGuardPaths.UpdateStatusPath, JsonSerializer.Serialize(status, Json));
    }
    private static void WriteCurrent(CurrentUpdateFile current)
    {
        Directory.CreateDirectory(AppGuardPaths.UpdateDirectory);
        File.WriteAllText(AppGuardPaths.UpdateCurrentPath, JsonSerializer.Serialize(current, Json));
    }
    private static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";
}
