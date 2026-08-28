using AppGuard.Core;

namespace AppGuard.Service;

public sealed class InstallationModeManager
{
    private readonly InstallationModeStore _store;
    private readonly PolicyHelper _policies;
    private readonly ApiClient _api;
    private readonly FileLogger _log;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public InstallationModeManager(InstallationModeStore store, PolicyHelper policies, ApiClient api, FileLogger log)
    {
        _store = store; _policies = policies; _api = api; _log = log;
    }

    public InstallationModeState Snapshot() => _store.Read();

    public async Task StartAsync(long requestId, int durationMinutes, string trigger, string actor, CancellationToken ct)
    {
        if (requestId <= 0) throw new ArgumentOutOfRangeException(nameof(requestId));
        if (durationMinutes is < 1 or > 240) throw new ArgumentOutOfRangeException(nameof(durationMinutes));
        await _gate.WaitAsync(ct);
        try
        {
            var current = _store.Read();
            if (current.Active) throw new InvalidOperationException($"Installation Mode is already active for request {current.InstallationId}.");
            await _policies.ReturnToLearningAsync(ct);
            var started = DateTimeOffset.UtcNow;
            var ends = started.AddMinutes(durationMinutes);
            var state = new InstallationModeState
            {
                Active = true, InstallationId = requestId, DurationMinutes = durationMinutes,
                Trigger = trigger ?? "", Actor = actor ?? "", StartedAt = started.ToString("O"), EndsAt = ends.ToString("O")
            };
            _store.Write(state);
            _log.Write($"installation-mode active id={requestId} duration={durationMinutes} trigger={trigger} ends={state.EndsAt}");
            await ReportOrQueueAsync(state, "active", "Installation Mode active.", null, ct);
        }
        finally { _gate.Release(); }
    }

    public async Task EndAsync(string reason, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var state = _store.Read();
            if (!state.Active || state.InstallationId <= 0) return;
            var completed = DateTimeOffset.UtcNow.ToString("O");
            try
            {
                await _policies.FinalizeInstallationModeAsync(state.InstallationId, ct);
                state.Active = false;
                _store.Write(state);
                await ReportOrQueueAsync(state, "completed", $"Installation Mode completed ({reason}). Enforcement restored.", completed, ct);
                _log.Write($"installation-mode completed id={state.InstallationId} reason={reason}");
            }
            catch (Exception finalizeError)
            {
                _log.Write($"installation-mode finalize failed id={state.InstallationId}: {finalizeError.Message}; forcing enforcement");
                try { await _policies.ForceEnforcementAsync(ct); }
                catch (Exception forceError)
                {
                    _log.Write($"installation-mode FORCE ENFORCEMENT FAILED id={state.InstallationId}: {forceError.Message}");
                    throw new InvalidOperationException("Installation Mode finalization failed and Enforcement could not be restored: " + forceError.Message, finalizeError);
                }
                state.Active = false;
                _store.Write(state);
                await ReportOrQueueAsync(state, "failed", "Installation learning was incomplete, but Enforcement was restored. " + finalizeError.Message, completed, ct);
            }
        }
        finally { _gate.Release(); }
    }

    public async Task CheckExpirationAsync(CancellationToken ct)
    {
        var state = _store.Read();
        if (!state.Active || string.IsNullOrWhiteSpace(state.EndsAt)) return;
        if (DateTimeOffset.TryParse(state.EndsAt, out var ends) && DateTimeOffset.UtcNow >= ends)
            await EndAsync("timer_expired", ct);
    }

    public async Task RetryPendingReportAsync(CancellationToken ct)
    {
        var state = _store.Read();
        if (string.IsNullOrWhiteSpace(state.PendingReportStatus) || state.InstallationId <= 0) return;
        try
        {
            await _api.ReportInstallationAsync(state.InstallationId, new InstallationReportRequest
            {
                Status = state.PendingReportStatus!, Detail = state.PendingReportDetail,
                StartedAt = state.PendingReportStartedAt, EndsAt = state.PendingReportEndsAt,
                CompletedAt = state.PendingReportCompletedAt
            }, ct);
            state.PendingReportStatus = state.PendingReportDetail = state.PendingReportStartedAt = state.PendingReportEndsAt = state.PendingReportCompletedAt = null;
            _store.Write(state);
        }
        catch (Exception ex) { _log.Write("installation report retry: " + ex.Message); }
    }

    private async Task ReportOrQueueAsync(InstallationModeState state, string status, string detail, string? completedAt, CancellationToken ct)
    {
        var report = new InstallationReportRequest { Status=status, Detail=detail, StartedAt=state.StartedAt, EndsAt=state.EndsAt, CompletedAt=completedAt };
        try { await _api.ReportInstallationAsync(state.InstallationId, report, ct); }
        catch (Exception ex)
        {
            state.PendingReportStatus=status; state.PendingReportDetail=detail; state.PendingReportStartedAt=state.StartedAt;
            state.PendingReportEndsAt=state.EndsAt; state.PendingReportCompletedAt=completedAt; _store.Write(state);
            _log.Write("installation report deferred: " + ex.Message);
        }
    }
}
