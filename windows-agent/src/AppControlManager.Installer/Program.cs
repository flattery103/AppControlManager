using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using Microsoft.Win32;

namespace AppControlManager.Installer;

internal static class Program
{
    private static readonly string Version = typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "0.15.0";

    [STAThread]
    static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        var parsed = Arguments.Parse(args);
        if (parsed.Silent)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(parsed.Server) || string.IsNullOrWhiteSpace(parsed.Key))
                    throw new InvalidOperationException("Silent installation requires /server and /key.");
                InstallerEngine.InstallAsync(parsed.Server, parsed.Key, parsed.StartLearning, null, CancellationToken.None).GetAwaiter().GetResult();
                Environment.ExitCode = 0;
            }
            catch (Exception ex)
            {
                try { Directory.CreateDirectory(@"C:\ProgramData\AppControlManager"); File.AppendAllText(@"C:\ProgramData\AppControlManager\installer.log", DateTimeOffset.Now + " " + ex + Environment.NewLine); } catch { }
                Environment.ExitCode = 1;
            }
            return;
        }
        Application.Run(new InstallForm(parsed.Server, parsed.Key, parsed.StartLearning));
    }

    private sealed record Arguments(string? Server, string? Key, bool Silent, bool StartLearning)
    {
        public static Arguments Parse(string[] args)
        {
            string? server=null,key=null; var silent=false; var learning=true;
            for (var i=0;i<args.Length;i++)
            {
                var a=args[i];
                if (a.Equals("/silent",StringComparison.OrdinalIgnoreCase) || a.Equals("--silent",StringComparison.OrdinalIgnoreCase)) silent=true;
                else if (a.Equals("/nolearning",StringComparison.OrdinalIgnoreCase) || a.Equals("--no-learning",StringComparison.OrdinalIgnoreCase)) learning=false;
                else if ((a.Equals("/server",StringComparison.OrdinalIgnoreCase) || a.Equals("--server",StringComparison.OrdinalIgnoreCase)) && i+1<args.Length) server=args[++i];
                else if ((a.Equals("/key",StringComparison.OrdinalIgnoreCase) || a.Equals("--key",StringComparison.OrdinalIgnoreCase)) && i+1<args.Length) key=args[++i];
            }
            return new(server,key,silent,learning);
        }
    }

    private sealed class InstallForm : Form
    {
        private readonly TextBox _server = new() { Width=430, PlaceholderText="http://server:8090" };
        private readonly TextBox _key = new() { Width=430, UseSystemPasswordChar=true, PlaceholderText="Organization enrollment key" };
        private readonly CheckBox _learning = new() { Text="Start device in Learning / Audit mode", Checked=true, AutoSize=true };
        private readonly Button _install = new() { Text="Install AppControl Manager", AutoSize=true };
        private readonly Label _status = new() { AutoSize=true, MaximumSize=new Size(500,0) };
        public InstallForm(string? server,string? key,bool learning)
        {
            Text=$"AppControl Manager {Version} Installer"; Width=580; Height=370; StartPosition=FormStartPosition.CenterScreen; MaximizeBox=false;
            _server.Text=server ?? ""; _key.Text=key ?? ""; _learning.Checked=learning;
            var panel=new FlowLayoutPanel { Dock=DockStyle.Fill, FlowDirection=FlowDirection.TopDown, WrapContents=false, Padding=new Padding(24), AutoScroll=true };
            panel.Controls.Add(new Label { Text="AppControl Manager", Font=new Font("Segoe UI",18,FontStyle.Bold), AutoSize=true });
            panel.Controls.Add(new Label { Text="Install and enroll this Windows endpoint.", AutoSize=true, Margin=new Padding(0,0,0,12) });
            panel.Controls.Add(new Label { Text="Server URL", AutoSize=true }); panel.Controls.Add(_server);
            panel.Controls.Add(new Label { Text="Enrollment key", AutoSize=true, Margin=new Padding(0,10,0,0) }); panel.Controls.Add(_key);
            panel.Controls.Add(_learning); panel.Controls.Add(_install); panel.Controls.Add(_status);
            Controls.Add(panel);
            _install.Click += async (_,__) => await InstallClicked();
        }
        private async Task InstallClicked()
        {
            _install.Enabled=false; _status.Text="Starting installation...";
            try
            {
                var progress=new Progress<string>(m=>_status.Text=m);
                await InstallerEngine.InstallAsync(_server.Text,_key.Text,_learning.Checked,progress,CancellationToken.None);
                _status.Text="Installation completed successfully. This device is enrolled and the AppControl Manager Agent is running.";
                MessageBox.Show(this,"AppControl Manager was installed successfully.","Installation Complete",MessageBoxButtons.OK,MessageBoxIcon.Information);
                Close();
            }
            catch(Exception ex)
            {
                _status.Text="Installation failed: "+ex.Message;
                MessageBox.Show(this,ex.Message,"Installation Failed",MessageBoxButtons.OK,MessageBoxIcon.Error);
                _install.Enabled=true;
            }
        }
    }

    private static class InstallerEngine
    {
        private static readonly string ProgramDataRoot=@"C:\ProgramData\AppControlManager";
        private static readonly string ProgramFilesRoot=@"C:\Program Files\AppControlManager";
        private sealed class EnrollResponse { public string device_id { get; set; }=""; public string device_key { get; set; }=""; }

        public static async Task InstallAsync(string server,string key,bool startLearning,IProgress<string>? progress,CancellationToken ct)
        {
            server=(server??"").Trim().TrimEnd('/'); key=(key??"").Trim();
            if (!Uri.TryCreate(server,UriKind.Absolute,out var serverUri) || (serverUri.Scheme!="http" && serverUri.Scheme!="https")) throw new InvalidOperationException("Enter a valid AppControl Manager server URL.");
            if (key.Length<8) throw new InvalidOperationException("Enter a valid organization enrollment key.");
            if (File.Exists(Path.Combine(ProgramDataRoot,"config.json"))) throw new InvalidOperationException("This endpoint is already enrolled. Use managed update or Upgrade-Agent.ps1 instead of the first-install package.");

            var temp=Path.Combine(Path.GetTempPath(),"AppControlManager-Install-"+Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temp);
            try
            {
                progress?.Report("Extracting embedded agent payload...");
                var zip=Path.Combine(temp,"agent-payload.zip");
                await using(var src=Assembly.GetExecutingAssembly().GetManifestResourceStream("AgentPayload") ?? throw new InvalidOperationException("Embedded agent payload is missing."))
                await using(var dst=File.Create(zip)) await src.CopyToAsync(dst,ct);
                var payload=Path.Combine(temp,"payload"); ZipFile.ExtractToDirectory(zip,payload,true);
                ValidatePayload(payload);

                progress?.Report("Enrolling this device...");
                using var http=new HttpClient { Timeout=TimeSpan.FromSeconds(60) };
                var body=new { hostname=Environment.MachineName, os_version=Environment.OSVersion.Version.ToString(), enrollment_token=key };
                var resp=await http.PostAsJsonAsync(server+"/api/enroll",body,ct);
                if(!resp.IsSuccessStatusCode) throw new InvalidOperationException($"Enrollment failed: HTTP {(int)resp.StatusCode} {await resp.Content.ReadAsStringAsync(ct)}");
                var enrolled=await resp.Content.ReadFromJsonAsync<EnrollResponse>(cancellationToken:ct) ?? throw new InvalidOperationException("Enrollment response was empty.");

                progress?.Report("Installing service, tray application and policy helpers...");
                Directory.CreateDirectory(ProgramDataRoot); Directory.CreateDirectory(ProgramFilesRoot); Directory.CreateDirectory(Path.Combine(ProgramFilesRoot,"Scripts")); Directory.CreateDirectory(Path.Combine(ProgramDataRoot,"Policies"));
                File.WriteAllText(Path.Combine(ProgramDataRoot,"config.json"),JsonSerializer.Serialize(new { server_url=server, device_id=enrolled.device_id, device_key=enrolled.device_key },new JsonSerializerOptions{WriteIndented=true}));
                File.Copy(Path.Combine(payload,"Service","AppControlManager.Service.exe"),Path.Combine(ProgramFilesRoot,"AppControlManager.Service.exe"),true);
                File.Copy(Path.Combine(payload,"Tray","AppControlManager.Tray.exe"),Path.Combine(ProgramFilesRoot,"AppControlManager.Tray.exe"),true);
                foreach(var script in Directory.EnumerateFiles(Path.Combine(payload,"scripts"),"*.ps1"))
                {
                    File.Copy(script,Path.Combine(ProgramFilesRoot,"Scripts",Path.GetFileName(script)),true);
                    File.Copy(script,Path.Combine(ProgramDataRoot,Path.GetFileName(script)),true);
                }

                Run("sc.exe",$"create AppControlManager binPath= \"{Path.Combine(ProgramFilesRoot,"AppControlManager.Service.exe")}\" start= auto DisplayName= \"AppControl Manager Agent\"");
                Run("sc.exe","description AppControlManager \"AppControl Manager application-control agent\"");
                using(var run=Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",true)) run?.SetValue("AppControlManagerTray",$"\"{Path.Combine(ProgramFilesRoot,"AppControlManager.Tray.exe")}\"");

                if(startLearning)
                {
                    progress?.Report("Enabling Windows App Control Learning / Audit mode...");
                    Run("powershell.exe",$"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{Path.Combine(ProgramFilesRoot,"Scripts","Start-LearningMode.ps1")}\" -NoTaskControl",timeoutMs:180000);
                }
                progress?.Report("Starting AppControl Manager Agent...");
                Run("sc.exe","start AppControlManager");
                try { Process.Start(new ProcessStartInfo(Path.Combine(ProgramFilesRoot,"AppControlManager.Tray.exe")){UseShellExecute=true}); } catch { }
            }
            finally { try { Directory.Delete(temp,true); } catch { } }
        }

        private static void ValidatePayload(string payload)
        {
            foreach(var file in new[]{ Path.Combine(payload,"Service","AppControlManager.Service.exe"), Path.Combine(payload,"Tray","AppControlManager.Tray.exe"), Path.Combine(payload,"scripts","Start-LearningMode.ps1") })
                if(!File.Exists(file)) throw new InvalidDataException("Installer payload is incomplete: "+file);
        }
        private static void Run(string exe,string args,int timeoutMs=60000)
        {
            using var p=Process.Start(new ProcessStartInfo(exe,args){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true}) ?? throw new InvalidOperationException("Could not start "+exe);
            if(!p.WaitForExit(timeoutMs)){ try{p.Kill(true);}catch{} throw new TimeoutException(exe+" timed out."); }
            var stdout=p.StandardOutput.ReadToEnd(); var stderr=p.StandardError.ReadToEnd();
            // sc.exe returns 1056 when a service is already running; first install rejects existing enrollment, so nonzero is a real error here.
            if(p.ExitCode!=0) throw new InvalidOperationException($"{exe} failed ({p.ExitCode}): {stderr} {stdout}".Trim());
        }
    }
}
