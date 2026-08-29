using System.Diagnostics;
using System.Text.Json;
using AppGuard.Core;
using Microsoft.Extensions.Hosting;

namespace AppGuard.Service;

public sealed class AgentWorker : BackgroundService
{
    private static readonly string Version = typeof(AgentWorker).Assembly.GetName().Version?.ToString(3) ?? "0.18.1";
    private readonly JsonFileStore _store;
    private readonly ApiClient _api;
    private readonly EventCollector _events;
    private readonly PolicyHelper _policies;
    private readonly AgentUpdater _updater;
    private readonly LocalRequestServer _pipe;
    private readonly BackgroundPolicyProcessor _backgroundPolicy;
    private readonly BackgroundPolicyStore _backgroundPolicyStore;
    private readonly InstallationModeManager _installationMode;
    private readonly FileLogger _log;
    private readonly CommandReceiptStore _receipts = new();
    private int _loop;

    public AgentWorker(JsonFileStore store, ApiClient api, EventCollector events, PolicyHelper policies, AgentUpdater updater, LocalRequestServer pipe, BackgroundPolicyProcessor backgroundPolicy, BackgroundPolicyStore backgroundPolicyStore, InstallationModeManager installationMode, FileLogger log)
    {
        _store = store; _api = api; _events = events; _policies = policies; _updater = updater; _pipe = pipe; _backgroundPolicy = backgroundPolicy; _backgroundPolicyStore = backgroundPolicyStore; _installationMode = installationMode; _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.Write($"agent-start version={Version} pid={Environment.ProcessId}");
        var pipeTask = _pipe.RunAsync(stoppingToken);
        var maintenanceTask = RunMaintenanceLoopAsync(stoppingToken);
        var commandTask = RunCommandLoopAsync(stoppingToken);
        var backgroundPolicyTask = RunBackgroundPolicyLoopAsync(stoppingToken);
        try
        {
            await Task.WhenAll(maintenanceTask, commandTask, backgroundPolicyTask, pipeTask);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        _log.Write("agent-stop");
    }

    private async Task RunMaintenanceLoopAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            _loop++;
            try { await HeartbeatAsync(stoppingToken); } catch (Exception ex) { _log.Write("heartbeat: " + ex.Message); }
            try { await UploadEventsAsync(stoppingToken); } catch (Exception ex) { _log.Write("events: " + ex.Message); }
            try { await _installationMode.CheckExpirationAsync(stoppingToken); } catch (Exception ex) { _log.Write("installation-expiry: " + ex.Message); }
            try { await _installationMode.RetryPendingReportAsync(stoppingToken); } catch (Exception ex) { _log.Write("installation-report: " + ex.Message); }
            // Long policy commands run on a separate command loop. Keep heartbeat, event upload,
            // and tray recovery alive so a healthy endpoint never appears Offline while Windows
            // App Control is building or installing a policy.
            if (_loop <= 4 || _loop % 20 == 0)
            {
                try { await EnsureInteractiveTrayAsync(stoppingToken); }
                catch (Exception ex) { _log.Write("tray-recovery: " + ex.Message); }
            }
            try { await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    private async Task RunCommandLoopAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await ProcessCommandsAsync(stoppingToken); } catch (Exception ex) { _log.Write("commands: " + ex.Message); }
            try { await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    private async Task RunBackgroundPolicyLoopAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var worked = false;
            try { worked = await _backgroundPolicy.ProcessOneAsync(stoppingToken); }
            catch (Exception ex) { _log.Write("background-policy: " + ex.Message); }
            try { await Task.Delay(TimeSpan.FromSeconds(worked ? 5 : 15), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    private async Task HeartbeatAsync(CancellationToken ct)
    {
        var mode = PolicyInspector.GetMode();
        var update = _updater.GetHeartbeatStatus(Version);
        var background = _backgroundPolicy.QueueStatus();
        await _api.HeartbeatAsync(new HeartbeatRequest
        {
            LearningMode = mode == "learning",
            PolicyMode = mode,
            ScriptEnforcementDisabled = PolicyInspector.IsScriptEnforcementDisabled(),
            AgentVersion = Version,
            OsVersion = Environment.OSVersion.Version.ToString(),
            UpdateStatus = update.Status,
            UpdateResult = update.Result,
            BackgroundPolicyStatus = background.Status,
            BackgroundPolicyPending = background.Pending,
            BackgroundPolicyFailed = background.Failed,
            BackgroundPolicyError = background.LastError,
            BackgroundPolicyOldestAt = background.OldestPendingAt
        }, ct);
        try { await _updater.CleanupPreviousTrustAsync(Version, ct); } catch (Exception ex) { _log.Write("agent-update cleanup: " + ex.Message); }
        if (_loop == 1 || _loop % 20 == 0) _log.Write("heartbeat OK mode=" + mode + (string.IsNullOrWhiteSpace(update.Status) ? "" : " update=" + update.Status));
    }

    private async Task EnsureInteractiveTrayAsync(CancellationToken ct)
    {
        if (Process.GetProcessesByName("AppControlManager.Tray").Length > 0) return;

        var script = Path.Combine(AppContext.BaseDirectory, "Scripts", "Ensure-TrayRunning.ps1");
        if (!File.Exists(script)) return;

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("Bypass");
        psi.ArgumentList.Add("-File");
        psi.ArgumentList.Add(script);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Could not start tray recovery helper.");
        await process.WaitForExitAsync(ct);
        var stdout = (await process.StandardOutput.ReadToEndAsync()).Trim();
        var stderr = (await process.StandardError.ReadToEndAsync()).Trim();
        if (process.ExitCode == 0)
        {
            if (Process.GetProcessesByName("AppControlManager.Tray").Length > 0)
            {
                _log.Write("tray-recovery: interactive tray is running");
                return;
            }

            throw new InvalidOperationException(string.IsNullOrWhiteSpace(stdout)
                ? "Tray recovery helper completed but AppControlManager.Tray.exe is still not running."
                : stdout);
        }

        throw new InvalidOperationException(string.IsNullOrWhiteSpace(stderr) ?
            (string.IsNullOrWhiteSpace(stdout) ? $"Tray recovery helper exited with code {process.ExitCode}." : stdout) : stderr);
    }

    private async Task UploadEventsAsync(CancellationToken ct)
    {
        var state = _store.ReadState();
        var events = _events.ReadAfter(state.LastRecordId);
        if (events.Count == 0) return;
        long maxRecord = state.LastRecordId;
        var uploaded = 0;
        foreach (var chunk in events.Chunk(20))
        {
            await _api.UploadEventsAsync(chunk, ct);
            maxRecord = chunk.Max(x => x.RecordId ?? maxRecord);
            _store.UpdateState(s => s.LastRecordId = maxRecord);
            uploaded += chunk.Length;

            if (PolicyInspector.GetMode().Equals("learning", StringComparison.OrdinalIgnoreCase))
            {
                var learned = chunk.Where(x => x.EventId == 3076).ToArray();
                if (learned.Length > 0)
                {
                    var stats = _backgroundPolicyStore.PrepareLearningEvents(learned);
                    _log.Write($"learning-prep observed={stats.Observed} productCandidates={stats.ProductCandidates} hashCandidates={stats.HashCandidates} reused={stats.Reused} queued={stats.Queued} ignoredEphemeral={stats.IgnoredEphemeral} unpreparable={stats.Unpreparable}");
                }
            }
        }
        _log.Write($"events uploaded count={uploaded} last_record={maxRecord}");
    }

    private async Task ProcessCommandsAsync(CancellationToken ct)
    {
        var commands = await _api.GetCommandsAsync(ct);
        var deviceId = _store.ReadConfig().DeviceId;
        foreach (var command in commands)
        {
            _log.Write($"command {command.Id} received type={command.CommandType}" + (string.IsNullOrWhiteSpace(command.ClaimToken) ? "" : " claimed"));
            var prior = _receipts.Find(deviceId, command);
            if (prior is not null)
            {
                prior.Completion.ClaimToken = command.ClaimToken;
                await _api.CompleteCommandAsync(command.Id, prior.Completion, ct);
                _log.Write($"command {command.Id} replay suppressed; saved completion reported success={prior.Completion.Success}");
                continue;
            }
            var complete = new CommandComplete { ClaimToken = command.ClaimToken };
            AgentUpdater.StagedAgentUpdate? stagedUpdate = null;
            var launchUninstall = false;
            try
            {
                switch (command.CommandType)
                {
                    case "approve_file":
                        var file = PayloadString(command, "file_path");
                        var policySource = PayloadString(command, "policy_source_path");
                        var requestId = PayloadLong(command, "request_id");
                        var scopedPolicyIdValue = PayloadLong(command, "scoped_policy_id");
                        long? scopedPolicyId = scopedPolicyIdValue > 0 ? scopedPolicyIdValue : null;
                        if (string.IsNullOrWhiteSpace(file)) throw new InvalidOperationException("Approved file path was empty.");
                        // Prefer the live installed path whenever it still exists. Protected-install bundle
                        // expansion depends on the real Program Files location. The preserved BlockedCache
                        // copy is only a fallback for transient files that have already disappeared.
                        var source = File.Exists(file) ? file : (!string.IsNullOrWhiteSpace(policySource) && File.Exists(policySource) ? policySource : file);
                        if (!File.Exists(source)) throw new FileNotFoundException("Approved file and its preserved approval copy no longer exist.", source);
                        var result = await _policies.ApproveFileAsync(source, requestId, scopedPolicyId, ct);
                        complete.Success = true;
                        complete.Result = result.ExpandedFiles > 0
                            ? $"Supplemental policy {result.PolicyId} installed for {file}. AppControl Manager also pre-authorized {result.ExpandedFiles} same-publisher component(s) from the protected application directory."
                            : $"Supplemental policy {result.PolicyId} installed for {file}.";
                        complete.PolicyId = result.PolicyId;
                        complete.RuleType = result.RuleType;
                        complete.FilePath = file;
                        complete.Sha256 = result.Sha256;
                        complete.Publisher = result.Publisher;
                        complete.ProductName = result.ProductName;
                        complete.FileVersion = result.FileVersion;
                        complete.BackgroundQueued = result.BackgroundQueued;
                        _log.Write($"command {command.Id} policy installed id={result.PolicyId} rule={result.RuleType} file={file} policyFiles={result.PolicyFiles} expanded={result.ExpandedFiles}");
                        break;
                    case "approve_session":
                        var sessionRequestId = PayloadLong(command, "request_id");
                        var sessionScopedPolicyIdValue = PayloadLong(command, "scoped_policy_id");
                        long? sessionScopedPolicyId = sessionScopedPolicyIdValue > 0 ? sessionScopedPolicyIdValue : null;
                        var components = PayloadComponents(command);
                        if (components.Count == 0) throw new InvalidOperationException("Approval session contained no components.");
                        var sources = components.Select(c => File.Exists(c.FilePath)
                                                    ? c.FilePath
                                                    : (!string.IsNullOrWhiteSpace(c.PolicySourcePath) && File.Exists(c.PolicySourcePath) ? c.PolicySourcePath! : c.FilePath))
                                                .Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                        if (sources.Length == 0) throw new FileNotFoundException("None of the approved session components are still available for policy generation.");
                        var sessionResult = await _policies.ApproveFilesAsync(sources, sessionRequestId, sessionScopedPolicyId, ct);
                        complete.Success = true;
                        complete.Result = sessionResult.ExpandedFiles > 0
                            ? $"Supplemental policy {sessionResult.PolicyId} installed for {sources.Length} requested component(s), plus {sessionResult.ExpandedFiles} same-publisher component(s) discovered in protected application directories."
                            : $"Supplemental policy {sessionResult.PolicyId} installed for {sources.Length} related component(s).";
                        complete.PolicyId = sessionResult.PolicyId;
                        complete.RuleType = sessionResult.RuleType;
                        complete.FilePath = components[0].FilePath;
                        complete.Sha256 = sessionResult.Sha256;
                        complete.Publisher = sessionResult.Publisher;
                        complete.ProductName = sessionResult.ProductName;
                        complete.FileVersion = sessionResult.FileVersion;
                        complete.BackgroundQueued = sessionResult.BackgroundQueued;
                        _log.Write($"command {command.Id} session policy installed id={sessionResult.PolicyId} rule={sessionResult.RuleType} requested={sources.Length} policyFiles={sessionResult.PolicyFiles} expanded={sessionResult.ExpandedFiles}");
                        break;
                    case "revoke_approval":
                        var revokePolicyId = PayloadString(command, "policy_id");
                        if (string.IsNullOrWhiteSpace(revokePolicyId)) throw new InvalidOperationException("Approval policy ID was empty.");
                        await _policies.RemovePolicyAsync(revokePolicyId, ct);
                        complete.Success = true;
                        complete.PolicyId = revokePolicyId;
                        complete.Result = $"Approval policy {revokePolicyId} removed. Other active policies may still allow the application.";
                        _log.Write($"command {command.Id} revoked approval policy id={revokePolicyId}");
                        break;
                    case "block_file":
                        var blockId = PayloadLong(command, "block_id");
                        var blockFile = PayloadString(command, "file_path");
                        var blockSource = PayloadString(command, "policy_source_path");
                        if (string.IsNullOrWhiteSpace(blockFile)) throw new InvalidOperationException("Blocked file path was empty.");
                        var blockPolicySource = !string.IsNullOrWhiteSpace(blockSource) && File.Exists(blockSource) ? blockSource : blockFile;
                        if (!File.Exists(blockPolicySource)) throw new FileNotFoundException("The application is no longer available on the endpoint, so a deny rule could not be generated.", blockPolicySource);
                        var blockResult = await _policies.BlockFileAsync(blockPolicySource, blockId, ct);
                        complete.Success = true;
                        complete.Result = $"Deny policy {blockResult.PolicyId} installed for {blockFile}.";
                        complete.PolicyId = blockResult.PolicyId;
                        complete.RuleType = blockResult.RuleType;
                        complete.FilePath = blockFile;
                        complete.Sha256 = blockResult.Sha256;
                        complete.Publisher = blockResult.Publisher;
                        complete.ProductName = blockResult.ProductName;
                        complete.FileVersion = blockResult.FileVersion;
                        _log.Write($"command {command.Id} deny policy installed id={blockResult.PolicyId} rule={blockResult.RuleType} file={blockFile}");
                        break;
                    case "unblock_file":
                        var denyPolicyId = PayloadString(command, "policy_id");
                        if (string.IsNullOrWhiteSpace(denyPolicyId)) throw new InvalidOperationException("Deny policy ID was empty.");
                        await _policies.RemovePolicyAsync(denyPolicyId, ct);
                        complete.Success = true;
                        complete.PolicyId = denyPolicyId;
                        complete.Result = $"Deny policy {denyPolicyId} removed.";
                        _log.Write($"command {command.Id} removed deny policy id={denyPolicyId}");
                        break;
                    case "update_agent":
                    {
                        var targetVersion = PayloadString(command, "target_version");
                        var expectedSha256 = PayloadString(command, "sha256");
                        var downloadPath = PayloadString(command, "download_path");
                        if (string.IsNullOrWhiteSpace(targetVersion) || string.IsNullOrWhiteSpace(expectedSha256) || string.IsNullOrWhiteSpace(downloadPath))
                            throw new InvalidOperationException("Agent update command was missing target version, SHA256, or download path.");
                        if (string.Equals(targetVersion, Version, StringComparison.OrdinalIgnoreCase))
                        {
                            complete.Success = true;
                            complete.Result = $"Agent is already running version {Version}.";
                            break;
                        }
                        stagedUpdate = await _updater.StageAsync(command.Id, targetVersion, expectedSha256, downloadPath, Version, ct);
                        complete.Success = true;
                        complete.Result = $"Agent {targetVersion} downloaded, SHA256 verified, staged and pre-authorized. Activation helper is starting with automatic rollback protection.";
                        _log.Write($"command {command.Id} agent update staged target={targetVersion}");
                        break;
                    }
                    case "uninstall_agent":
                        complete.Success = true;
                        complete.Result = "Remote offboarding accepted. AppControl Manager policies will be removed before the service, tray, program files and local data are removed.";
                        launchUninstall = true;
                        _log.Write($"command {command.Id} remote uninstall accepted");
                        break;
                    case "return_to_learning":
                        await _policies.ReturnToLearningAsync(ct);
                        complete.Success = true;
                        complete.Result = "Device returned to Learning/Audit mode and learning cursor reset.";
                        _log.Write($"command {command.Id} returned device to learning mode");
                        break;
                    case "enable_enforcement":
                        await _policies.EnableEnforcementAsync(ct);
                        complete.Success = true;
                        complete.Result = "Device switched to Enforcement mode and learned applications were baselined.";
                        _log.Write($"command {command.Id} enabled enforcement mode");
                        break;
                    case "start_installation_mode":
                        var installationId = PayloadLong(command, "installation_id");
                        var installationDuration = (int)PayloadLong(command, "duration_minutes");
                        await _installationMode.StartAsync(installationId, installationDuration, PayloadString(command, "trigger") ?? "server", PayloadString(command, "actor") ?? "administrator", ct);
                        complete.Success = true;
                        complete.Result = $"Installation Mode started for {installationDuration} minutes.";
                        _log.Write($"command {command.Id} started Installation Mode id={installationId} duration={installationDuration}");
                        break;
                    case "end_installation_mode":
                        var endingInstallationId = PayloadLong(command, "installation_id");
                        await _installationMode.EndAsync(PayloadString(command, "reason") ?? "server_requested", ct);
                        complete.Success = true;
                        complete.Result = $"Installation Mode {endingInstallationId} ended and Enforcement was restored.";
                        _log.Write($"command {command.Id} ended Installation Mode id={endingInstallationId}");
                        break;
                    case "retry_background_policy":
                        var retried = _backgroundPolicyStore.RetryFailedWork();
                        complete.Success = true;
                        complete.Result = $"Reset {retried.RulesReset} failed rule job(s) and {retried.BundlesReset} failed bundle job(s) to queued.";
                        _log.Write($"command {command.Id} retried background policy work rules={retried.RulesReset} bundles={retried.BundlesReset}");
                        break;
                    default:
                        throw new InvalidOperationException("Unknown command type " + command.CommandType);
                }
            }
            catch (Exception ex)
            {
                complete.Success = false;
                complete.Result = ex.Message;
                _log.Write($"command {command.Id} failed: {ex.Message}");
            }
            if (complete.Success) _receipts.Save(deviceId, command, complete);
            await _api.CompleteCommandAsync(command.Id, complete, ct);
            _log.Write($"command {command.Id} completion reported success={complete.Success}");
            if (complete.Success && stagedUpdate is not null)
            {
                _updater.LaunchActivation(stagedUpdate, Version);
                // The detached helper will stop this service after the command result reaches the server.
                // Do not claim another command while activation is underway.
                return;
            }
            if (complete.Success && launchUninstall)
            {
                LaunchRemoteUninstall();
                // The detached helper removes policies and then stops/deletes this service.
                return;
            }
        }
    }

    private void LaunchRemoteUninstall()
    {
        var source = Path.Combine(AppGuardPaths.ScriptsDirectory, "Apply-AgentUninstall.ps1");
        if (!File.Exists(source)) throw new FileNotFoundException("Remote uninstall helper is missing.", source);
        var temp = Path.Combine(Path.GetTempPath(), $"AppControlManager-Offboard-{Guid.NewGuid():N}.ps1");
        File.Copy(source, temp, true);
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetTempPath()
        };
        psi.ArgumentList.Add("-NoLogo");
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("Bypass");
        psi.ArgumentList.Add("-File");
        psi.ArgumentList.Add(temp);
        var proc = Process.Start(psi) ?? throw new InvalidOperationException("Could not start remote uninstall helper.");
        proc.Dispose();
        _log.Write("remote uninstall helper launched");
    }

    private sealed class CommandComponent
    {
        public string FilePath { get; set; } = "";
        public string? PolicySourcePath { get; set; }
    }

    private static List<CommandComponent> PayloadComponents(AgentCommand command)
    {
        if (!command.Payload.TryGetValue("components", out var value) || value is null) return [];
        if (value is JsonElement e && e.ValueKind == JsonValueKind.Array)
        {
            var result = new List<CommandComponent>();
            foreach (var item in e.EnumerateArray())
            {
                var file = item.TryGetProperty("file_path", out var fp) ? fp.GetString() : null;
                var source = item.TryGetProperty("policy_source_path", out var sp) && sp.ValueKind != JsonValueKind.Null ? sp.GetString() : null;
                if (!string.IsNullOrWhiteSpace(file)) result.Add(new CommandComponent { FilePath = file!, PolicySourcePath = source });
            }
            return result;
        }
        return [];
    }

    private static string? PayloadString(AgentCommand command, string name)
    {
        if (!command.Payload.TryGetValue(name, out var value) || value is null) return null;
        if (value is JsonElement e) return e.ValueKind == JsonValueKind.String ? e.GetString() : e.ToString();
        return value.ToString();
    }

    private static long PayloadLong(AgentCommand command, string name)
    {
        if (!command.Payload.TryGetValue(name, out var value) || value is null) return 0;
        if (value is JsonElement e && e.TryGetInt64(out var n)) return n;
        return long.TryParse(value.ToString(), out var parsed) ? parsed : 0;
    }
}
