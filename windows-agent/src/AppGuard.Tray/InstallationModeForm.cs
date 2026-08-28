using AppGuard.Core;

namespace AppGuard.Tray;

public sealed class InstallationModeForm : Form
{
    private readonly string _requestedBy;
    private readonly long _installationId;
    private readonly DateTimeOffset _endsAt;
    private readonly Label _remaining = new() { AutoSize=true };
    private readonly Button _finish = new() { Text="Finish Installation Early", AutoSize=true };
    private readonly System.Windows.Forms.Timer _timer = new() { Interval=1000 };
    public TimeSpan TimeRemaining => _endsAt - DateTimeOffset.UtcNow;

    public InstallationModeForm(InstallationModeState state, string requestedBy)
    {
        _requestedBy=requestedBy; _installationId=state.InstallationId;
        if (!DateTimeOffset.TryParse(state.EndsAt, out var parsedEndsAt)) parsedEndsAt = DateTimeOffset.UtcNow;
        _endsAt = parsedEndsAt;
        UiTheme.ApplyForm(this); Text="AppControl Manager - Installation Mode"; Width=560; Height=250; StartPosition=FormStartPosition.CenterScreen;
        var title=new Label { Text="INSTALLATION MODE ACTIVE", AutoSize=true, Font=new Font(SystemFonts.MessageBoxFont.FontFamily,15,FontStyle.Bold) }; UiTheme.StyleHeadline(title);
        var body=new Label { Text="Install or update the approved software now. AppControl Manager will automatically restore Enforcement when time expires.", AutoSize=true, MaximumSize=new Size(500,0) }; UiTheme.StyleBody(body);
        UiTheme.StyleBody(_remaining); UiTheme.StylePrimaryButton(_finish); _finish.Click += async (_,_)=>await FinishAsync();
        var table=new TableLayoutPanel { Dock=DockStyle.Fill, Padding=new Padding(22), RowCount=4, ColumnCount=1 }; table.Controls.Add(title,0,0); table.Controls.Add(body,0,1); table.Controls.Add(_remaining,0,2); table.Controls.Add(_finish,0,3); Controls.Add(table);
        _timer.Tick += (_,_)=>UpdateCountdown(); _timer.Start(); UpdateCountdown();
        FormClosed += (_,_)=>_timer.Dispose();
    }
    public void UpdateFrom(InstallationModeState state) { UpdateCountdown(); }
    private void UpdateCountdown()
    {
        var left=TimeRemaining; if(left<TimeSpan.Zero) left=TimeSpan.Zero;
        _remaining.Text=$"Time remaining: {(int)left.TotalMinutes:00}:{left.Seconds:00}";
        if(left==TimeSpan.Zero) _finish.Enabled=false;
    }
    private async Task FinishAsync()
    {
        _finish.Enabled=false; _remaining.Text="Finalizing installation and restoring Enforcement...";
        try { var r=await PipeClient.SendAsync(new PipeRequest { Action="finish_installation", InstallationId=_installationId, RequestedBy=_requestedBy }); if(!r.Ok){ _remaining.Text=r.Message; _finish.Enabled=true; } }
        catch(Exception ex){ _remaining.Text=ex.Message; _finish.Enabled=true; }
    }
}
