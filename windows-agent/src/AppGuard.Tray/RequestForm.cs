using System.Diagnostics;
using AppGuard.Core;

namespace AppGuard.Tray;

public sealed class RequestForm : Form
{
    private readonly TextBox _path = new() { Dock = DockStyle.Fill, ReadOnly = true };
    private readonly TextBox _reason = new() { Dock = DockStyle.Fill, Multiline = true, Height = 58 };
    private readonly Label _product = new() { AutoSize = true };
    private readonly Label _publisher = new() { AutoSize = true, MaximumSize = new Size(520, 0) };
    private readonly Label _version = new() { AutoSize = true };
    private readonly Label _parent = new() { AutoSize = true, MaximumSize = new Size(520, 0) };
    private readonly Label _headline = new() { AutoSize = true, Font = new Font(SystemFonts.MessageBoxFont.FontFamily, 15, FontStyle.Bold) };
    private readonly Label _status = new() { AutoSize = true, MaximumSize = new Size(540, 0) };
    private readonly Button _submit = new() { Text = "Request Access", AutoSize = true };
    private readonly Button _install = new() { Text = "Request Installation", AutoSize = true, Visible = false };
    private readonly Button _block = new() { Text = "Block on This Device", AutoSize = true, Visible = false };
    private readonly Button _run = new() { Text = "Run Application", AutoSize = true, Visible = false };
    private readonly Button _close = new() { Text = "Close", AutoSize = true };
    private readonly string _requestedBy;
    private readonly long? _blockedRecordId;
    private readonly BlockedSnapshot? _snapshot;
    private readonly bool _allowUserBlock;

    public long? RequestId { get; private set; }
    public string FilePath => _path.Text;
    public event Action<RequestForm, long>? RequestCreated;

    public RequestForm(string? initialPath, bool blocked, string requestedBy, long? blockedRecordId = null, BlockedSnapshot? snapshot = null)
    {
        _requestedBy = requestedBy;
        _blockedRecordId = blockedRecordId;
        _snapshot = snapshot;
        _allowUserBlock = blocked;
        UiTheme.ApplyForm(this);
        Text = blocked ? "AppControl Manager - Application Blocked" : "AppControl Manager - Request Application Access";
        Width = 680;
        Height = 470;
        MinimumSize = new Size(620, 430);
        StartPosition = FormStartPosition.CenterScreen;
        ShowInTaskbar = true;
        TopMost = blocked;

        UiTheme.StyleHeadline(_headline);
        UiTheme.StyleBody(_status, muted: true);
        UiTheme.StyleInput(_path);
        UiTheme.StyleInput(_reason);
        UiTheme.StylePrimaryButton(_submit);
        UiTheme.StyleSecondaryButton(_install);
        UiTheme.StyleDangerButton(_block);
        UiTheme.StylePrimaryButton(_run);
        UiTheme.StyleSecondaryButton(_close);

        _headline.Text = blocked ? "Application Blocked" : "Request Application Access";
        _path.Text = initialPath ?? "";

        var browse = new Button { Text = "Browse...", AutoSize = true, Enabled = !blocked };
        UiTheme.StyleSecondaryButton(browse);
        browse.Click += (_, _) => Browse();
        _submit.Click += async (_, _) => await SubmitAsync();
        _install.Click += async (_, _) => await RequestInstallationAsync();
        _block.Click += async (_, _) => await BlockOnDeviceAsync();
        _run.Click += (_, _) => RunApplication();
        _close.Click += (_, _) => Close();

        var table = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(22),
            BackColor = UiTheme.CardBack,
            RowCount = 10,
            ColumnCount = 3,
            AutoScroll = true
        };
        table.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        table.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        table.Controls.Add(_headline, 0, 0); table.SetColumnSpan(_headline, 3);
        var explanation = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(600, 0),
            Text = blocked
                ? "Windows App Control prevented this application from running because it is not currently approved. You can request access below."
                : "Select an application and submit an approval request to your administrator."
        };
        UiTheme.StyleBody(explanation, muted: true);
        table.Controls.Add(explanation, 0, 1); table.SetColumnSpan(explanation, 3);

        table.Controls.Add(new Label { Text = "Application:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 2);
        table.Controls.Add(_path, 1, 2); table.Controls.Add(browse, 2, 2);
        table.Controls.Add(new Label { Text = "Product:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 3);
        table.Controls.Add(_product, 1, 3); table.SetColumnSpan(_product, 2);
        table.Controls.Add(new Label { Text = "Publisher:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 4);
        table.Controls.Add(_publisher, 1, 4); table.SetColumnSpan(_publisher, 2);
        table.Controls.Add(new Label { Text = "Version:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 5);
        table.Controls.Add(_version, 1, 5); table.SetColumnSpan(_version, 2);
        table.Controls.Add(new Label { Text = "Launched by:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 6);
        _parent.Text = _snapshot?.ParentPath ?? "";
        table.Controls.Add(_parent, 1, 6); table.SetColumnSpan(_parent, 2);
        table.Controls.Add(new Label { Text = "Reason:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 7);
        table.Controls.Add(_reason, 1, 7); table.SetColumnSpan(_reason, 2);

        _install.Visible = blocked;
        _block.Visible = _allowUserBlock;
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        buttons.Controls.Add(_submit); buttons.Controls.Add(_install); buttons.Controls.Add(_block); buttons.Controls.Add(_run); buttons.Controls.Add(_close);
        table.Controls.Add(buttons, 1, 8); table.SetColumnSpan(buttons, 2);
        table.Controls.Add(_status, 1, 9); table.SetColumnSpan(_status, 2);
        Controls.Add(table);
        AcceptButton = _submit;
        CancelButton = _close;

        LoadMetadata();
        Shown += (_, _) => { TopMost = false; Activate(); };
    }

    private void Browse()
    {
        using var dialog = new OpenFileDialog { Filter = "Applications (*.exe)|*.exe|All files (*.*)|*.*", CheckFileExists = true };
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            _path.Text = dialog.FileName;
            LoadMetadata();
        }
    }

    private void LoadMetadata()
    {
        if (string.IsNullOrWhiteSpace(_path.Text))
        {
            _product.Text = ""; _publisher.Text = ""; _version.Text = "";
            return;
        }
        if (File.Exists(_path.Text))
        {
            var meta = FileMetadataReader.Read(_path.Text);
            _product.Text = string.IsNullOrWhiteSpace(meta.ProductName) ? Path.GetFileName(meta.FilePath) : meta.ProductName;
            _publisher.Text = string.IsNullOrWhiteSpace(meta.Publisher) ? "Unsigned / publisher unavailable" : meta.Publisher;
            _version.Text = meta.FileVersion ?? "";
            return;
        }
        _product.Text = string.IsNullOrWhiteSpace(_snapshot?.ProductName) ? Path.GetFileName(_path.Text) : _snapshot.ProductName;
        _publisher.Text = string.IsNullOrWhiteSpace(_snapshot?.Publisher) ? "Temporary component / publisher unavailable" : _snapshot.Publisher;
        _version.Text = _snapshot?.FileVersion ?? "";
    }

    private async Task SubmitAsync()
    {
        if (string.IsNullOrWhiteSpace(_path.Text) || (!_blockedRecordId.HasValue && !File.Exists(_path.Text)))
        {
            MessageBox.Show(this, "Select an existing application first.", "AppControl Manager", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _submit.Enabled = false;
        _block.Enabled = false;
        _reason.Enabled = false;
        _status.Text = "Submitting request...";
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest
            {
                Action = "request",
                FilePath = _path.Text.Trim(),
                Reason = _reason.Text.Trim(),
                RequestedBy = _requestedBy,
                RecordId = _blockedRecordId
            });
            _status.Text = response.Message;
            if (!response.Ok)
            {
                _reason.Enabled = true;
                _submit.Enabled = true;
                _block.Enabled = _allowUserBlock;
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
            _block.Enabled = _allowUserBlock;
            MessageBox.Show(this, "Could not contact the AppControl Manager service.\n\n" + ex.Message, "AppControl Manager", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private async Task RequestInstallationAsync()
    {
        if (string.IsNullOrWhiteSpace(_path.Text)) return;
        _submit.Enabled = false; _install.Enabled = false; _block.Enabled = false; _reason.Enabled = false;
        _status.Text = "Submitting installation request...";
        try
        {
            var response = await PipeClient.SendAsync(new PipeRequest { Action = "request_installation", FilePath = _path.Text.Trim(), Reason = _reason.Text.Trim(), RequestedBy = _requestedBy, RecordId = _blockedRecordId });
            _status.Text = response.Message;
            if (response.Ok) { _headline.Text = "Installation Request Pending"; _submit.Visible=false; _install.Visible=false; _block.Visible=false; }
            else { _submit.Enabled=true; _install.Enabled=true; _block.Enabled=_allowUserBlock; _reason.Enabled=true; }
        }
        catch (Exception ex)
        {
            _status.Text=ex.Message; _submit.Enabled=true; _install.Enabled=true; _block.Enabled=_allowUserBlock; _reason.Enabled=true;
        }
    }

    private async Task BlockOnDeviceAsync()
    {
        if (!_allowUserBlock || string.IsNullOrWhiteSpace(_path.Text)) return;
        var app = string.IsNullOrWhiteSpace(_product.Text) ? Path.GetFileName(_path.Text) : _product.Text;
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
                Action = "block",
                FilePath = _path.Text.Trim(),
                Reason = _reason.Text.Trim(),
                RequestedBy = _requestedBy,
                RecordId = _blockedRecordId
            });
            if (!response.Ok)
            {
                _status.Text = response.Message;
                _reason.Enabled = true;
                _submit.Enabled = true;
                _block.Enabled = true;
                return;
            }
            Close();
        }
        catch (Exception ex)
        {
            _status.Text = ex.Message;
            _reason.Enabled = true;
            _submit.Enabled = true;
            _block.Enabled = true;
            MessageBox.Show(this, "Could not create the device block.\n\n" + ex.Message, "AppControl Manager", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    public void UpdateRequestStatus(ApprovalStatusInfo request)
    {
        if (RequestId.HasValue && request.Id != RequestId.Value) return;
        RequestId ??= request.Id;
        var note = request.DecisionNote;
        ApplyStatus(request.Status, note);
    }

    private void ApplyStatus(string status, string? note)
    {
        var normalized = status.ToLowerInvariant();
        var locked = normalized is "pending" or "approving" or "approved" or "approved_existing" or "denied" or "approval_failed" or "blocked" or "revoked";
        _reason.Enabled = !locked;
        _submit.Visible = !locked;
        _install.Visible = false;
        _block.Visible = _allowUserBlock && !locked;
        _run.Visible = false;

        switch (normalized)
        {
            case "pending":
                _headline.Text = "Access Request Pending";
                _status.Text = $"Request #{RequestId} has been sent and is waiting for administrator review.";
                break;
            case "approving":
                _headline.Text = "Application Is Being Approved";
                _status.Text = $"Request #{RequestId} was approved by an administrator. AppControl Manager is installing the allow policy on this computer.";
                break;
            case "approved":
            case "approved_existing":
                _headline.Text = "Application Approved";
                _run.Visible = File.Exists(_path.Text);
                _status.Text = _run.Visible
                    ? "This application is approved. You can run it now."
                    : "Approval is complete. Re-run the original application or installer.";
                break;
            case "denied":
                _headline.Text = "Access Request Denied";
                _status.Text = "This application was not approved." + NoteSuffix(note);
                break;
            case "approval_failed":
                _headline.Text = "Approval Could Not Be Applied";
                _status.Text = "The administrator approved this request, but the endpoint could not install the allow policy." + NoteSuffix(note);
                break;
            case "blocked":
                _headline.Text = "Application Blocked by Administrator";
                _status.Text = "This application has an explicit AppControl Manager deny policy and cannot be requested again." + NoteSuffix(note);
                break;
            case "revoked":
                _headline.Text = "Application Approval Revoked";
                _status.Text = "The previous AppControl Manager approval for this application has been revoked." + NoteSuffix(note);
                break;
            default:
                _status.Text = note ?? status;
                _submit.Visible = true;
                _submit.Enabled = true;
                _reason.Enabled = true;
                break;
        }
    }

    private static string NoteSuffix(string? note) => string.IsNullOrWhiteSpace(note) ? "" : "\n\nAdministrator / policy note: " + note;

    public void UpdatePolicyProgress(PolicyProgressInfo progress)
    {
        if (!RequestId.HasValue || progress.RequestId != RequestId.Value) return;
        if (!string.IsNullOrWhiteSpace(progress.Message)) _status.Text = progress.Message;
    }

    private void RunApplication()
    {
        _run.Enabled = false;
        try
        {
            Process.Start(new ProcessStartInfo(_path.Text) { UseShellExecute = true });
            Close();
        }
        catch (Exception ex)
        {
            _run.Enabled = true;
            MessageBox.Show(this, "The application could not be started.\n\n" + ex.Message, "AppControl Manager", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
