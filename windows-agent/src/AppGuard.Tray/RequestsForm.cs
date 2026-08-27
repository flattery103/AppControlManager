using AppGuard.Core;

namespace AppGuard.Tray;

public sealed class RequestsForm : Form
{
    private readonly ListView _list = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true };
    private readonly Label _summary = new() { AutoSize = true };

    public RequestsForm()
    {
        UiTheme.ApplyForm(this);
        Text = "AppControl Manager - Request History";
        Width = 900;
        Height = 430;
        StartPosition = FormStartPosition.CenterScreen;
        UiTheme.StyleList(_list);
        UiTheme.StyleBody(_summary, muted: true);
        _list.Columns.Add("ID", 55);
        _list.Columns.Add("Application", 300);
        _list.Columns.Add("Status", 100);
        _list.Columns.Add("Requested", 150);
        _list.Columns.Add("Reason / Decision", 300);

        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(18), RowCount = 2, ColumnCount = 1, BackColor = UiTheme.CardBack };
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        panel.Controls.Add(_summary, 0, 0);
        panel.Controls.Add(_list, 0, 1);
        Controls.Add(panel);
    }

    public void UpdateRequests(IReadOnlyList<ApprovalStatusInfo> requests)
    {
        _list.BeginUpdate();
        try
        {
            _list.Items.Clear();
            foreach (var request in requests.OrderByDescending(r => r.Id))
            {
                var app = string.IsNullOrWhiteSpace(request.ProductName) ? Path.GetFileName(request.FilePath) : request.ProductName;
                if (request.ComponentCount > 1) app = $"{app} (+{request.ComponentCount - 1} related)";
                var detail = request.Status is "denied" or "approval_failed" ? request.DecisionNote : request.Reason;
                var item = new ListViewItem(request.Id.ToString());
                item.SubItems.Add(app ?? request.FilePath);
                item.SubItems.Add(FriendlyStatus(request.Status));
                item.SubItems.Add(FormatTime(request.CreatedAt));
                item.SubItems.Add(detail ?? "");
                item.Tag = request;
                _list.Items.Add(item);
            }
        }
        finally { _list.EndUpdate(); }

        var active = requests.Count(r => r.Status is "pending" or "approving");
        _summary.Text = active == 0
            ? "No approval requests are currently waiting. Recent requests are shown below."
            : $"{active} approval request(s) are currently pending or being applied.";
    }

    private static string FriendlyStatus(string status) => status switch
    {
        "pending" => "Pending",
        "approving" => "Approving",
        "approved" => "Approved",
        "approved_existing" => "Approved",
        "denied" => "Denied",
        "approval_failed" => "Failed",
        "revoked" => "Revoked",
        "blocked" => "Blocked",
        _ => status
    };

    private static string FormatTime(string? value)
    {
        if (DateTimeOffset.TryParse(value, out var dt)) return dt.ToLocalTime().ToString("g");
        return value ?? "";
    }
}
