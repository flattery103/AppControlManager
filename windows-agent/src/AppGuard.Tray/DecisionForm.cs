using System.Diagnostics;
using AppGuard.Core;

namespace AppGuard.Tray;

public sealed class DecisionForm : Form
{
    private readonly ApprovalStatusInfo _request;

    public DecisionForm(ApprovalStatusInfo request)
    {
        _request = request;
        UiTheme.ApplyForm(this);
        var approved = request.Status is "approved" or "approved_existing";
        var revoked = request.Status == "revoked";
        Text = approved ? "AppControl Manager - Application Approved" : revoked ? "AppControl Manager - Approval Revoked" : request.Status == "denied" ? "AppControl Manager - Request Denied" : "AppControl Manager - Approval Failed";
        Width = 590;
        Height = 300;
        StartPosition = FormStartPosition.CenterScreen;
        TopMost = true;
        ShowInTaskbar = true;

        var headline = new Label
        {
            AutoSize = true,
            Text = approved ? "Application Approved" : revoked ? "Application Approval Revoked" : request.Status == "denied" ? "Access Request Denied" : "Approval Could Not Be Applied"
        };
        UiTheme.StyleHeadline(headline);
        var app = string.IsNullOrWhiteSpace(request.ProductName) ? Path.GetFileName(request.FilePath) : request.ProductName;
        var message = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(530, 0),
            Text = approved
                ? (File.Exists(request.FilePath)
                    ? $"{app} is approved. You can run it now."
                    : $"{app} is approved. Re-run the original application or installer.")
                : revoked
                    ? $"The previous AppControl Manager approval for {app} was revoked by an administrator."
                    : request.Status == "denied"
                        ? $"{app} was not approved."
                        : $"{app} was approved by the administrator, but AppControl Manager could not apply the policy on this computer."
        };
        UiTheme.StyleBody(message);
        var note = new Label { AutoSize = true, MaximumSize = new Size(530, 0), Text = approved ? "" : request.DecisionNote ?? "" };
        UiTheme.StyleBody(note, muted: true);
        var run = new Button { Text = "Run Application", AutoSize = true, Visible = approved && File.Exists(request.FilePath) };
        var close = new Button { Text = "Close", AutoSize = true };
        UiTheme.StylePrimaryButton(run);
        UiTheme.StyleSecondaryButton(close);
        run.Click += (_, _) => RunApplication(run);
        close.Click += (_, _) => Close();

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true };
        buttons.Controls.Add(run); buttons.Controls.Add(close);
        var table = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), RowCount = 5, ColumnCount = 1, BackColor = UiTheme.CardBack };
        table.Controls.Add(headline, 0, 0);
        table.Controls.Add(message, 0, 1);
        table.Controls.Add(new Label { AutoSize = true, Text = request.FilePath, Visible = !approved }, 0, 2);
        table.Controls.Add(note, 0, 3);
        table.Controls.Add(buttons, 0, 4);
        Controls.Add(table);
        Shown += (_, _) => { TopMost = false; Activate(); };
    }

    private void RunApplication(Button runButton)
    {
        runButton.Enabled = false;
        try
        {
            Process.Start(new ProcessStartInfo(_request.FilePath) { UseShellExecute = true });
            Close();
        }
        catch (Exception ex)
        {
            runButton.Enabled = true;
            MessageBox.Show(this, ex.Message, "AppControl Manager", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
