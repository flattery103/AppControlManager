using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using AppGuard.Core;

namespace AppGuard.Tray;

public sealed class TrayContext : ApplicationContext
{
    private readonly NotifyIcon _icon;
    private readonly SynchronizationContext _ui;
    private readonly System.Windows.Forms.Timer _requestTimer;
    private readonly System.Windows.Forms.Timer _sessionQuietTimer;
    private readonly ToolStripMenuItem _statusMenuItem;
    private readonly ToolStripMenuItem _approvedInstallationMenuItem;
    private readonly string _requestedBy;
    private EventLogWatcher? _watcher;
    private string? _lastBlockedPath;
    private BlockedSnapshot? _lastBlockedSnapshot;
    private RequestsForm? _requestsForm;
    private SessionRequestForm? _activeSessionForm;
    private readonly Dictionary<long, RequestForm> _requestForms = new();
    private readonly Dictionary<long, SessionRequestForm> _sessionRequestForms = new();
    private readonly Dictionary<long, string> _lastStatuses = new();
    private readonly HashSet<long> _shownInstallationApprovals = [];
    private InstallationStatusInfo? _approvedInstallation;
    private InstallationApprovalForm? _installationApprovalForm;
    private InstallationModeForm? _installationModeForm;
    private bool _haveStatusSnapshot;
    private bool _refreshingRequests;
    private readonly Dictionary<string, DateTimeOffset> _recentNotices = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _recentBlocks = new(StringComparer.OrdinalIgnoreCase);
    private Action? _balloonClickAction;

    private static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan BlockDedupe = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan NoticeDedupe = TimeSpan.FromSeconds(15);

    public TrayContext(SynchronizationContext ui)
    {
        _ui = ui;
        _requestedBy = $"{Environment.UserDomainName}\\{Environment.UserName}";

        var menu = new ContextMenuStrip();
        menu.Items.Add("Request application approval...", null, (_, _) => OpenManualRequest(_lastBlockedPath));
        menu.Items.Add("Request History...", null, async (_, _) => await ShowRequestsAsync());
        _approvedInstallationMenuItem = new ToolStripMenuItem("Approved installation...") { Enabled = false };
        _approvedInstallationMenuItem.Click += (_, _) => ShowApprovedInstallation();
        menu.Items.Add(_approvedInstallationMenuItem);
        _statusMenuItem = new ToolStripMenuItem("Checking...") { Enabled = false };
        menu.Items.Add(_statusMenuItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => ExitThread());
        _icon = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Text = "AppControl Manager",
            Visible = true,
            ContextMenuStrip = menu
        };
        _icon.DoubleClick += (_, _) => OpenManualRequest(_lastBlockedPath);
        _icon.BalloonTipClicked += (_, _) =>
        {
            var action = _balloonClickAction;
            _balloonClickAction = null;
            action?.Invoke();
        };

        _requestTimer = new System.Windows.Forms.Timer { Interval = 5000 };
        _requestTimer.Tick += async (_, _) => await RefreshRequestsAsync(false);
        _requestTimer.Start();

        _sessionQuietTimer = new System.Windows.Forms.Timer { Interval = 1800 };
        _sessionQuietTimer.Tick += (_, _) =>
        {
            _sessionQuietTimer.Stop();
            if (_activeSessionForm is not null && !_activeSessionForm.IsDisposed && !_activeSessionForm.IsSubmitted)
                _activeSessionForm.SetCollecting(false);
        };

        StartWatcher();
        _ = RefreshRequestsAsync(false);
    }

    private void StartWatcher()
    {
        try
        {
            var query = new EventLogQuery("Microsoft-Windows-CodeIntegrity/Operational", PathType.LogName, "*[System[(EventID=3077)]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += (_, e) =>
            {
                if (e.EventRecord is null) return;
                try
                {
                    using (e.EventRecord)
                    {
                        var (path, parent) = ExtractPaths(e.EventRecord.ToXml());
                        if (string.IsNullOrWhiteSpace(path)) return;
                        var resolved = DevicePathResolver.Resolve(path);
                        var resolvedParent = DevicePathResolver.Resolve(parent);
                        if (string.IsNullOrWhiteSpace(resolved)) return;
                        var recordId = e.EventRecord.RecordId ?? 0;
                        _ = CaptureAndHandleAsync(resolved, resolvedParent, recordId);
                    }
                }
                catch { }
            };
            _watcher.Enabled = true;
        }
        catch { }
    }

    private static (string? FilePath, string? ParentPath) ExtractPaths(string xml)
    {
        var doc = XDocument.Parse(xml);
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        string? file = null, parent = null;
        foreach (var d in doc.Descendants(ns + "Data"))
        {
            var name = (string?)d.Attribute("Name");
            if (name is "File Name" or "FileName") file = d.Value;
            else if (name is "Process Name" or "ProcessName") parent = d.Value;
        }
        return (file, parent);
    }

    private async Task CaptureAndHandleAsync(string path, string? parentPath, long recordId)
    {
        BlockedSnapshot? snapshot = null;
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest
            {
                Action = "capture", FilePath = path, ParentPath = parentPath, RecordId = recordId, RequestedBy = _requestedBy
            });
            if (response.Ok) snapshot = response.Snapshot;
        }
        catch { }

        if (snapshot is null)
        {
            snapshot = new BlockedSnapshot
            {
                RecordId = recordId,
                OriginalPath = path,
                ParentPath = parentPath,
                ProductName = Path.GetFileName(path),
                CapturedAt = DateTimeOffset.UtcNow.ToString("O")
            };
        }

        // Only applications explicitly blocked by an AppControl Manager deny policy are silent.
        // Unknown/unapproved Windows App Control blocks still open the normal Request Access flow.
        // This preserves central telemetry without making an administrator-created explicit block
        // requestable from the endpoint.
        PipeResponse? disposition = null;
        ApprovalStatusInfo? activeRequest = null;
        if (!IsWerFault(snapshot.ParentPath))
        {
            try { disposition = await GetDispositionAsync(snapshot); } catch { }
            if (!string.Equals(disposition?.Disposition, "blocked", StringComparison.OrdinalIgnoreCase))
            {
                try { activeRequest = await FindActiveRequestAsync(snapshot); } catch { }
            }
        }

        _ui.Post(_ =>
        {
            _lastBlockedPath = snapshot.OriginalPath;
            _lastBlockedSnapshot = snapshot;
            HandleBlockedSnapshot(snapshot, activeRequest, disposition);
        }, null);
    }

    private async Task<PipeResponse?> GetDispositionAsync(BlockedSnapshot snapshot)
    {
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest
            {
                Action = "disposition",
                FilePath = snapshot.OriginalPath,
                RecordId = snapshot.RecordId,
                RequestedBy = _requestedBy
            });
            return response.Ok ? response : null;
        }
        catch { return null; }
    }

    private async Task<ApprovalStatusInfo?> FindActiveRequestAsync(BlockedSnapshot snapshot)
    {
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest { Action = "requests", RequestedBy = _requestedBy });
            if (!response.Ok) return null;
            return response.Requests
                .Where(r => r.Status is "pending" or "approving")
                .FirstOrDefault(r => RequestMatchesSnapshot(r, snapshot));
        }
        catch { return null; }
    }

    private static bool RequestMatchesSnapshot(ApprovalStatusInfo request, BlockedSnapshot snapshot)
    {
        if (!string.IsNullOrWhiteSpace(snapshot.Sha256) && !string.IsNullOrWhiteSpace(request.Sha256)
            && string.Equals(snapshot.Sha256, request.Sha256, StringComparison.OrdinalIgnoreCase))
            return true;
        if (!string.IsNullOrWhiteSpace(snapshot.OriginalPath)
            && string.Equals(snapshot.OriginalPath, request.FilePath, StringComparison.OrdinalIgnoreCase))
            return true;

        foreach (var component in request.Components)
        {
            if (!string.IsNullOrWhiteSpace(snapshot.Sha256) && !string.IsNullOrWhiteSpace(component.Sha256)
                && string.Equals(snapshot.Sha256, component.Sha256, StringComparison.OrdinalIgnoreCase))
                return true;
            if (!string.IsNullOrWhiteSpace(snapshot.OriginalPath)
                && string.Equals(snapshot.OriginalPath, component.FilePath, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private void HandleBlockedSnapshot(BlockedSnapshot snapshot, ApprovalStatusInfo? activeRequest, PipeResponse? disposition)
    {
        _lastBlockedPath = snapshot.OriginalPath;

        // Windows Error Reporting often generates its own temporary helper blocks after an application fails.
        // They remain in telemetry but are not surfaced as separate user approval windows.
        if (IsWerFault(snapshot.ParentPath)) return;

        if (string.Equals(disposition?.Disposition, "blocked", StringComparison.OrdinalIgnoreCase))
        {
            // Explicit AppControl Manager BLOCK policies are intentionally silent on the endpoint.
            // The Code Integrity event is still collected and uploaded to the server.
            return;
        }

        if (string.Equals(disposition?.Disposition, "revoked", StringComparison.OrdinalIgnoreCase))
        {
            // Revoke means "no longer approved", not "prohibited". Fall through to the normal
            // grouped Request Access flow so related EXE/DLL blocks are collected into one request.
        }

        if (string.Equals(disposition?.Disposition, "approved", StringComparison.OrdinalIgnoreCase))
        {
            ShowShortNotice(
                "Application blocked",
                $"Windows App Control blocked {DisplayName(snapshot)} even though an AppControl Manager approval exists. Contact your administrator if this continues.",
                ToolTipIcon.Warning,
                "approved-but-blocked|" + snapshot.OriginalPath);
            return;
        }

        // Suppress only duplicate UI. The file remains blocked and each Code Integrity event
        // is still uploaded by the service for central telemetry.
        if (IsRepeatedBlock(snapshot)) return;

        // If this component is already part of a Pending/Approving request, do not let the user
        // create another request. Reopen the existing request status instead.
        if (activeRequest is not null)
        {
            if (_sessionRequestForms.TryGetValue(activeRequest.Id, out var existing) && !existing.IsDisposed)
            {
                existing.AddComponent(snapshot);
                existing.UpdateRequestStatus(activeRequest);
                existing.Show();
                existing.WindowState = FormWindowState.Normal;
                existing.Activate();
                return;
            }

            var statusForm = CreateSessionForm();
            statusForm.AddComponent(snapshot);
            statusForm.SetCollecting(false);
            statusForm.UpdateRequestStatus(activeRequest);
            _sessionRequestForms[activeRequest.Id] = statusForm;
            _lastStatuses[activeRequest.Id] = activeRequest.Status;
            statusForm.Show();
            statusForm.Activate();
            return;
        }

        var now = DateTimeOffset.Now;
        var canJoin = _activeSessionForm is not null
                      && !_activeSessionForm.IsDisposed
                      && !_activeSessionForm.IsSubmitted
                      && now - _activeSessionForm.StartedAt <= SessionLifetime
                      && now - _activeSessionForm.LastActivityAt <= TimeSpan.FromSeconds(30);

        if (!canJoin)
        {
            _activeSessionForm = CreateSessionForm();
            _activeSessionForm.Show();
            _activeSessionForm.Activate();
        }

        _activeSessionForm!.AddComponent(snapshot);
        _activeSessionForm.SetCollecting(true);
        _sessionQuietTimer.Stop();
        _sessionQuietTimer.Start();
    }

    private bool IsRepeatedBlock(BlockedSnapshot snapshot)
    {
        var identity = !string.IsNullOrWhiteSpace(snapshot.Sha256)
            ? "sha256|" + snapshot.Sha256
            : "path|" + snapshot.OriginalPath;
        var now = DateTimeOffset.Now;
        var repeated = _recentBlocks.TryGetValue(identity, out var last) && now - last < BlockDedupe;
        _recentBlocks[identity] = now;
        foreach (var stale in _recentBlocks.Where(x => now - x.Value > BlockDedupe).Select(x => x.Key).ToArray())
            _recentBlocks.Remove(stale);
        return repeated;
    }

    private SessionRequestForm CreateSessionForm()
    {
        var form = new SessionRequestForm(_requestedBy);
        form.RequestCreated += (f, id) =>
        {
            _sessionRequestForms[id] = f;
            _lastStatuses[id] = "pending";
            _ = RefreshRequestsAsync(false);
        };
        form.FormClosed += (_, _) =>
        {
            var ids = _sessionRequestForms.Where(kv => ReferenceEquals(kv.Value, form)).Select(kv => kv.Key).ToArray();
            foreach (var id in ids) _sessionRequestForms.Remove(id);
            if (ReferenceEquals(_activeSessionForm, form)) _activeSessionForm = null;
        };
        return form;
    }

    private static string DisplayName(BlockedSnapshot snapshot)
    {
        return string.IsNullOrWhiteSpace(snapshot.ProductName)
            ? Path.GetFileName(snapshot.OriginalPath)
            : snapshot.ProductName;
    }

    private void ShowShortNotice(string title, string text, ToolTipIcon icon, string dedupeKey, Action? clickAction = null)
    {
        var now = DateTimeOffset.Now;
        if (_recentNotices.TryGetValue(dedupeKey, out var last) && now - last < NoticeDedupe) return;
        _recentNotices[dedupeKey] = now;
        foreach (var stale in _recentNotices.Where(kv => now - kv.Value > TimeSpan.FromMinutes(5)).Select(kv => kv.Key).ToArray())
            _recentNotices.Remove(stale);

        _balloonClickAction = clickAction;
        _icon.BalloonTipTitle = title;
        _icon.BalloonTipText = text;
        _icon.BalloonTipIcon = icon;
        _icon.ShowBalloonTip(5000);
    }

    private static bool IsWerFault(string? parentPath)
    {
        if (string.IsNullOrWhiteSpace(parentPath)) return false;
        return string.Equals(Path.GetFileName(parentPath), "WerFault.exe", StringComparison.OrdinalIgnoreCase)
               || string.Equals(Path.GetFileName(parentPath), "WerFaultSecure.exe", StringComparison.OrdinalIgnoreCase);
    }

    private RequestForm CreateRequestForm(string? path, bool blocked, long? recordId = null, BlockedSnapshot? snapshot = null)
    {
        var form = new RequestForm(path, blocked, _requestedBy, recordId, snapshot);
        form.RequestCreated += (f, id) =>
        {
            _requestForms[id] = f;
            _lastStatuses[id] = "pending";
            _ = RefreshRequestsAsync(false);
        };
        form.FormClosed += (_, _) =>
        {
            var ids = _requestForms.Where(kv => ReferenceEquals(kv.Value, form)).Select(kv => kv.Key).ToArray();
            foreach (var id in ids) _requestForms.Remove(id);
        };
        return form;
    }

    private void OpenManualRequest(string? path)
    {
        var snapshot = _lastBlockedSnapshot is not null
                       && !string.IsNullOrWhiteSpace(path)
                       && string.Equals(_lastBlockedSnapshot.OriginalPath, path, StringComparison.OrdinalIgnoreCase)
            ? _lastBlockedSnapshot
            : null;
        var form = CreateRequestForm(path, blocked: false, snapshot?.RecordId, snapshot);
        form.Show();
        form.Activate();
    }

    private void SetTrayStatus(string? mode, bool online, int activeRequests = 0)
    {
        var label = !online ? "Offline" : ((mode ?? "").ToLowerInvariant() switch
        {
            "learning" => "Learning",
            "enforcement" => "Enforced",
            _ => "Unknown"
        });
        _statusMenuItem.Text = label;
        _icon.Text = activeRequests > 0
            ? $"AppControl Manager - {label} - {activeRequests} request(s) pending"
            : $"AppControl Manager - {label}";
    }

    private async Task ShowRequestsAsync()
    {
        if (_requestsForm is null || _requestsForm.IsDisposed)
        {
            _requestsForm = new RequestsForm();
            _requestsForm.FormClosed += (_, _) => _requestsForm = null;
        }
        _requestsForm.Show();
        _requestsForm.WindowState = FormWindowState.Normal;
        _requestsForm.Activate();
        await RefreshRequestsAsync(true);
    }

    private void ShowApprovedInstallation()
    {
        if (_approvedInstallation is null) return;
        if (_installationApprovalForm is not null && !_installationApprovalForm.IsDisposed)
        {
            _installationApprovalForm.Show();
            _installationApprovalForm.WindowState = FormWindowState.Normal;
            _installationApprovalForm.Activate();
            return;
        }
        _installationApprovalForm = new InstallationApprovalForm(_approvedInstallation, _requestedBy);
        _installationApprovalForm.FormClosed += (_, _) => _installationApprovalForm = null;
        _installationApprovalForm.Show();
        _installationApprovalForm.Activate();
    }

    private async Task RefreshRequestsAsync(bool showErrors)
    {
        if (_refreshingRequests) return;
        _refreshingRequests = true;
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest { Action = "status", RequestedBy = _requestedBy });
            if (!response.Ok) throw new InvalidOperationException(response.Message);
            var requests = response.Requests.OrderByDescending(r => r.Id).ToList();
            _requestsForm?.UpdateRequests(requests);
            var installations = response.Installations.OrderByDescending(x => x.Id).ToList();
            var approvedInstallation = installations.FirstOrDefault(x => x.Status.Equals("approved", StringComparison.OrdinalIgnoreCase));
            _approvedInstallation = approvedInstallation;
            _approvedInstallationMenuItem.Enabled = approvedInstallation is not null;
            if (approvedInstallation is not null && _shownInstallationApprovals.Add(approvedInstallation.Id))
                ShowApprovedInstallation();

            var installationMode = response.InstallationMode;
            if (installationMode is not null && installationMode.Active)
            {
                if (_installationModeForm is null || _installationModeForm.IsDisposed)
                {
                    _installationModeForm = new InstallationModeForm(installationMode, _requestedBy);
                    _installationModeForm.Show();
                }
                else _installationModeForm.UpdateFrom(installationMode);
            }
            else if (_installationModeForm is not null && !_installationModeForm.IsDisposed)
            {
                _installationModeForm.Close();
                _installationModeForm = null;
            }

            PolicyProgressInfo? progress = null;
            if (requests.Any(r => r.Status == "approving"))
            {
                try
                {
                    var progressResponse = await PipeClient.SendAsync(new PipeRequest { Action = "progress", RequestedBy = _requestedBy });
                    if (progressResponse.Ok) progress = progressResponse.Progress;
                }
                catch { }
            }

            var active = requests.Count(r => r.Status is "pending" or "approving");
            SetTrayStatus(response.Mode, online: true, active);

            foreach (var request in requests)
            {
                if (_requestForms.TryGetValue(request.Id, out var requestForm) && !requestForm.IsDisposed)
                    requestForm.UpdateRequestStatus(request);
                if (_sessionRequestForms.TryGetValue(request.Id, out var sessionForm) && !sessionForm.IsDisposed)
                    sessionForm.UpdateRequestStatus(request);

                if (progress is not null && progress.RequestId == request.Id)
                {
                    if (_requestForms.TryGetValue(request.Id, out var progressRequestForm) && !progressRequestForm.IsDisposed)
                        progressRequestForm.UpdatePolicyProgress(progress);
                    if (_sessionRequestForms.TryGetValue(request.Id, out var progressSessionForm) && !progressSessionForm.IsDisposed)
                        progressSessionForm.UpdatePolicyProgress(progress);
                }

                var old = _lastStatuses.TryGetValue(request.Id, out var prior) ? prior : null;
                if (_haveStatusSnapshot && !string.Equals(old, request.Status, StringComparison.OrdinalIgnoreCase) && IsFinal(request.Status))
                {
                    var singleOpen = _requestForms.TryGetValue(request.Id, out var f) && !f.IsDisposed;
                    var sessionOpen = _sessionRequestForms.TryGetValue(request.Id, out var sf) && !sf.IsDisposed;
                    if (!singleOpen && !sessionOpen)
                    {
                        if (request.Status == "revoked")
                        {
                            var app = string.IsNullOrWhiteSpace(request.ProductName) ? Path.GetFileName(request.FilePath) : request.ProductName;
                            ShowShortNotice("Application approval revoked", $"{app} is no longer approved.", ToolTipIcon.Info, "revoked-request|" + request.Id);
                        }
                        else
                        {
                            ShowDecision(request);
                        }
                    }
                }
                _lastStatuses[request.Id] = request.Status;
            }
            _haveStatusSnapshot = true;
        }
        catch (Exception ex)
        {
            SetTrayStatus(null, online: false);
            if (showErrors)
                MessageBox.Show("Could not retrieve request history because AppControl Manager is offline.\n\n" + ex.Message, "AppControl Manager", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally { _refreshingRequests = false; }
    }

    private void ShowDecision(ApprovalStatusInfo request)
    {
        var form = new DecisionForm(request);
        form.Show();
        form.Activate();
    }

    private static bool IsFinal(string status) => status is "approved" or "approved_existing" or "denied" or "approval_failed" or "revoked";

    protected override void ExitThreadCore()
    {
        _requestTimer.Stop();
        _requestTimer.Dispose();
        _sessionQuietTimer.Stop();
        _sessionQuietTimer.Dispose();
        if (_watcher is not null) { _watcher.Enabled = false; _watcher.Dispose(); }
        if (_activeSessionForm is not null && !_activeSessionForm.IsDisposed) _activeSessionForm.Close();
        if (_requestsForm is not null && !_requestsForm.IsDisposed) _requestsForm.Close();
        _icon.Visible = false;
        _icon.Dispose();
        base.ExitThreadCore();
    }
}
