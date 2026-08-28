using AppGuard.Core;

namespace AppGuard.Tray;

public sealed class InstallationApprovalForm : Form
{
    private readonly InstallationStatusInfo _installation;
    private readonly string _requestedBy;
    private readonly Label _status = new() { AutoSize=true, MaximumSize=new Size(560,0) };
    private readonly Button _start = new() { Text="Start Installation", AutoSize=true };
    private readonly Button _later = new() { Text="Not Now", AutoSize=true };

    public InstallationApprovalForm(InstallationStatusInfo installation, string requestedBy)
    {
        _installation=installation; _requestedBy=requestedBy;
        UiTheme.ApplyForm(this); Text="AppControl Manager - Installation Approved"; Width=620; Height=300; StartPosition=FormStartPosition.CenterScreen; TopMost=true;
        UiTheme.StylePrimaryButton(_start); UiTheme.StyleSecondaryButton(_later); UiTheme.StyleBody(_status, muted:true);
        var title=new Label { Text="Installation Approved", AutoSize=true, Font=new Font(SystemFonts.MessageBoxFont.FontFamily,15,FontStyle.Bold) }; UiTheme.StyleHeadline(title);
        var duration=installation.DurationMinutes ?? 15;
        var body=new Label { AutoSize=true, MaximumSize=new Size(560,0), Text=$"Your administrator approved a {duration}-minute installation period. When you are ready, click Start Installation. The timer begins only after you click Start." }; UiTheme.StyleBody(body);
        _status.Text=string.IsNullOrWhiteSpace(installation.ActivationExpiresAt) ? "" : "This approval must be started before " + installation.ActivationExpiresAt + ".";
        _start.Click += async (_,_) => await StartAsync(); _later.Click += (_,_)=>Close();
        var buttons=new FlowLayoutPanel { AutoSize=true, Dock=DockStyle.Fill }; buttons.Controls.Add(_start); buttons.Controls.Add(_later);
        var table=new TableLayoutPanel { Dock=DockStyle.Fill, Padding=new Padding(22), RowCount=4, ColumnCount=1 }; table.Controls.Add(title,0,0); table.Controls.Add(body,0,1); table.Controls.Add(_status,0,2); table.Controls.Add(buttons,0,3); Controls.Add(table);
        Shown += (_,_)=>{ TopMost=false; Activate(); };
    }
    private async Task StartAsync()
    {
        _start.Enabled=false; _status.Text="Starting Installation Mode...";
        try
        {
            var r=await PipeClient.SendAsync(new PipeRequest { Action="start_installation", InstallationId=_installation.Id, RequestedBy=_requestedBy });
            if(!r.Ok){ _status.Text=r.Message; _start.Enabled=true; return; }
            Close();
        }
        catch(Exception ex){ _status.Text=ex.Message; _start.Enabled=true; }
    }
}
