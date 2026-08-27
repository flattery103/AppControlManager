using System.Diagnostics;
using AppGuard.Core;

namespace AppGuard.Tray;

/// <summary>
/// Presents one user-facing approval request for a burst of related WDAC blocks.
/// The tray adds components for a short collection window before enabling Request Access.
/// </summary>
public sealed class SessionRequestForm : Form
{
    private readonly string _requestedBy;
    private readonly string _sessionKey = Guid.NewGuid().ToString("N");
    private readonly List<BlockedSnapshot> _components = [];
    private readonly HashSet<long> _recordIds = [];
    private readonly ListView _list = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true };
    private readonly TextBox _reason = new() { Dock = DockStyle.Fill, Multiline = true, Height = 62 };
    private readonly Label _headline = new() { AutoSize = true, Font = new Font(SystemFonts.MessageBoxFont.FontFamily, 15, FontStyle.Bold) };
    private readonly Label _summary = new() { AutoSize = true, MaximumSize = new Size(700, 0) };
    private readonly Label _status = new() { AutoSize = true, MaximumSize = new Size(700, 0) };
    private readonly Button _submit = new() { Text = "Request Access", AutoSize = true, Enabled = false };
    private readonly Button _block = new() { Text = "Block on This Device", AutoSize = true, Enabled = false };
    private readonly Button _run = new() { Text = "Run Application", AutoSize = true, Visible = false };
    private readonly Button _close = new() { Text = "Close", AutoSize = true };
    private bool _collecting = true;
    private int _requestComponentCount = 1;

    public DateTimeOffset StartedAt { get; } = DateTimeOffset.Now;
    public DateTimeOffset LastActivityAt { get; private set; } = DateTimeOffset.Now;
    public bool IsSubmitted => RequestId.HasValue || !_submit.Visible;
    public long? RequestId { get; private set; }
    public string PrimaryPath => _components.FirstOrDefault()?.OriginalPath ?? "";
    public event Action<SessionRequestForm, long>? RequestCreated;

    public SessionRequestForm(string requestedBy)
    {
        _requestedBy = requestedBy;
        UiTheme.ApplyForm(this);
        Text = "AppControl Manager - Application Blocked";
        Width = 820;
        Height = 560;
        MinimumSize = new Size(720, 500);
        StartPosition = FormStartPosition.CenterScreen;
        ShowInTaskbar = true;
        TopMost = true;

        UiTheme.StyleHeadline(_headline);
        UiTheme.StyleBody(_summary, muted: true);
        UiTheme.StyleBody(_status, muted: true);
        UiTheme.StyleList(_list);
        UiTheme.StyleInput(_reason);
        UiTheme.StylePrimaryButton(_submit);
        UiTheme.StyleDangerButton(_block);
        UiTheme.StylePrimaryButton(_run);
        UiTheme.StyleSecondaryButton(_close);

        _headline.Text = "Application Blocked";
        _summary.Text = "AppControl Manager is collecting related blocked components from this launch attempt...";
        _status.Text = "Request Access will become available after the related activity settles.";

        _list.Columns.Add("Application / component", 260);
        _list.Columns.Add("Publisher", 260);
        _list.Columns.Add("Version", 125);
        _list.Columns.Add("Loaded by", 260);

        _submit.Click += async (_, _) => await SubmitAsync();
        _block.Click += async (_, _) => await BlockOnDeviceAsync();
        _run.Click += (_, _) => RunApplication();
        _close.Click += (_, _) => Close();

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        buttons.Controls.Add(_submit); buttons.Controls.Add(_block); buttons.Controls.Add(_run); buttons.Controls.Add(_close);

        var table = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), RowCount = 8, ColumnCount = 2, BackColor = UiTheme.CardBack };
        table.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        table.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        table.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
        table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        table.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        table.Controls.Add(_headline, 0, 0); table.SetColumnSpan(_headline, 2);
        table.Controls.Add(_summary, 0, 1); table.SetColumnSpan(_summary, 2);
        table.Controls.Add(_list, 0, 2); table.SetColumnSpan(_list, 2);
        table.Controls.Add(new Label { Text = "Reason:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 3);
        table.Controls.Add(_reason, 1, 4);
        table.Controls.Add(buttons, 1, 5);
        table.Controls.Add(_status, 1, 6);
        Controls.Add(table);
        CancelButton = _close;
        Shown += (_, _) => { TopMost = false; Activate(); };
    }

    public void AddComponent(BlockedSnapshot snapshot)
    {
        if (snapshot.RecordId <= 0 || !_recordIds.Add(snapshot.RecordId)) return;
        _components.Add(snapshot);
        LastActivityAt = DateTimeOffset.Now;

        var product = string.IsNullOrWhiteSpace(snapshot.ProductName) ? Path.GetFileName(snapshot.OriginalPath) : snapshot.ProductName;
        var publisher = string.IsNullOrWhiteSpace(snapshot.Publisher) ? "Publisher unavailable" : snapshot.Publisher;
        var item = new ListViewItem(product ?? snapshot.OriginalPath);
        item.SubItems.Add(publisher);
        item.SubItems.Add(snapshot.FileVersion ?? "");
        item.SubItems.Add(snapshot.ParentPath ?? "");
        item.ToolTipText = snapshot.OriginalPath;
        _list.Items.Add(item);
        UpdateSummary();
    }

    public void SetCollecting(bool collecting)
    {
        if (IsSubmitted) return;
        _collecting = collecting;
        _submit.Enabled = !collecting && _components.Count > 0;
        _block.Enabled = !collecting && _components.Count > 0;
        _status.Text = collecting
            ? "Collecting related components..."
            : $"{_components.Count} related component(s) detected. Request access, or block the application only on this device.";
        UpdateSummary();
    }

    private void UpdateSummary()
    {
        if (_components.Count == 0)
        {
            _summary.Text = "AppControl Manager is collecting related blocked components from this launch attempt...";
            return;
        }
        var primary = _components[0];
        var app = string.IsNullOrWhiteSpace(primary.ProductName) ? Path.GetFileName(primary.OriginalPath) : primary.ProductName;
        _summary.Text = _collecting
            ? $"{app}: {_components.Count} blocked component(s) detected so far. AppControl Manager is still collecting related activity."
            : $"{app}: {_components.Count} related blocked component(s) detected. Request access, or block this application on this device.";
    }

    private async Task SubmitAsync()
    {
        if (_collecting || _recordIds.Count == 0) return;
        _submit.Enabled = false;
        _block.Enabled = false;
        _reason.Enabled = false;
        _status.Text = "Submitting grouped approval request...";
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest
            {
                Action = "request_session",
                Reason = _reason.Text.Trim(),
                RequestedBy = _requestedBy,
                ComponentRecordIds = _recordIds.ToList(),
                SessionKey = _sessionKey
            });
            _status.Text = response.Message;
            if (!response.Ok)
            {
                _reason.Enabled = true;
                _submit.Enabled = true;
                _block.Enabled = true;
                return;
            }

            RequestId = response.RequestId;
            if (RequestId.HasValue) RequestCreated?.Invoke(this, RequestId.Value);
            ApplyStatus(response.AlreadyApproved ? "approved" : response.RequestStatus ?? "pending", response.Message);
        }
        catch (Exception ex)
        {
            _status.Text = ex.Message;
            _reason.Enabled = true;
            _submit.Enabled = true;
            _block.Enabled = true;
            MessageBox.Show(this, "Could not contact the AppControl Manager service.\n\n" + ex.Message, "AppControl Manager", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private async Task BlockOnDeviceAsync()
    {
        if (_collecting || _recordIds.Count == 0) return;
        var primary = _components.FirstOrDefault();
        var app = primary is null || string.IsNullOrWhiteSpace(primary.ProductName)
            ? Path.GetFileName(primary?.OriginalPath ?? "this application")
            : primary.ProductName;
        var confirm = MessageBox.Show(this,
            $"Block {app} on this device?\n\nFuture attempts to run it will be silently blocked and logged on the AppControl Manager server. An administrator can remove the block later.",
            "Block on This Device", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes) return;

        _submit.Enabled = false;
        _block.Enabled = false;
        _reason.Enabled = false;
        _status.Text = "Creating a device-only block...";
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest
            {
                Action = "block_session",
                Reason = _reason.Text.Trim(),
                RequestedBy = _requestedBy,
                ComponentRecordIds = _recordIds.ToList(),
                SessionKey = _sessionKey
            });
            if (!response.Ok)
            {
                _status.Text = response.Message;
                _reason.Enabled = true;
                _submit.Enabled = !_collecting;
                _block.Enabled = !_collecting;
                return;
            }

            _headline.Text = "Blocked on This Device";
            _status.Text = response.Message;
            Close();
        }
        catch (Exception ex)
        {
            _status.Text = ex.Message;
            _reason.Enabled = true;
            _submit.Enabled = !_collecting;
            _block.Enabled = !_collecting;
            MessageBox.Show(this, "Could not create the device block.\n\n" + ex.Message, "AppControl Manager", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    public void UpdateRequestStatus(ApprovalStatusInfo request)
    {
        if (RequestId.HasValue && request.Id != RequestId.Value) return;
        RequestId ??= request.Id;
        _requestComponentCount = Math.Max(request.ComponentCount, 1);
        ApplyStatus(request.Status, request.DecisionNote);
    }

    private void ApplyStatus(string status, string? note)
    {
        var normalized = status.ToLowerInvariant();
        _reason.Enabled = false;
        _submit.Visible = false;
        _block.Visible = false;
        _run.Visible = false;
        var count = Math.Max(Math.Max(_components.Count, _requestComponentCount), 1);

        switch (normalized)
        {
            case "pending":
                _headline.Text = "Access Request Pending";
                _status.Text = $"Request #{RequestId} covers {count} related component(s) and is waiting for administrator review.";
                break;
            case "approving":
                _headline.Text = "Application Is Being Approved";
                _status.Text = $"Request #{RequestId} was approved. AppControl Manager is installing one allow policy for the related components.";
                break;
            case "approved":
            case "approved_existing":
                _headline.Text = "Application Approved";
                _run.Visible = File.Exists(PrimaryPath) && Path.GetExtension(PrimaryPath).Equals(".exe", StringComparison.OrdinalIgnoreCase);
                _status.Text = _run.Visible
                    ? $"The application and its {count} related component(s) are approved. You can run the application now." + NoteSuffix(note)
                    : $"The related components are approved. Re-run the original application or installer." + NoteSuffix(note);
                break;
            case "denied":
                _headline.Text = "Access Request Denied";
                _status.Text = "This application session was not approved." + NoteSuffix(note);
                break;
            case "approval_failed":
                _headline.Text = "Approval Could Not Be Applied";
                _status.Text = "The administrator approved the request, but AppControl Manager could not apply the policy on this computer." + NoteSuffix(note);
                break;
            case "blocked":
                _headline.Text = "Application Blocked by Administrator";
                _status.Text = "One or more components in this application session are explicitly blocked by AppControl Manager policy." + NoteSuffix(note);
                break;
            case "revoked":
                _headline.Text = "Application Approval Revoked";
                _status.Text = "The previous AppControl Manager approval for this application session has been revoked." + NoteSuffix(note);
                break;
        }
    }

    public void UpdatePolicyProgress(PolicyProgressInfo progress)
    {
        if (!RequestId.HasValue || progress.RequestId != RequestId.Value) return;
        if (!string.IsNullOrWhiteSpace(progress.Message)) _status.Text = progress.Message;
    }

    private void RunApplication()
    {
        if (!File.Exists(PrimaryPath)) return;
        _run.Enabled = false;
        try
        {
            Process.Start(new ProcessStartInfo(PrimaryPath) { UseShellExecute = true });
            Close();
        }
        catch (Exception ex)
        {
            _run.Enabled = true;
            MessageBox.Show(this, ex.Message, "AppControl Manager", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static string NoteSuffix(string? note) => string.IsNullOrWhiteSpace(note) ? "" : "\n\n" + note;
}
