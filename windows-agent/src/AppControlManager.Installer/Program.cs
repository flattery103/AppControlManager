using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;

namespace AppControlManager.Installer;

internal static class Program
{
    private static readonly string Version = typeof(Program).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
        .InformationalVersion.Split('+')[0] ?? "1.0.0-rc.1";

    [STAThread]
    static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        var parsed = Arguments.Parse(args);
        if (parsed.Silent)
        {
            try
            {
                if (!InstallerEngine.ExistingInstallDetected &&
                    (string.IsNullOrWhiteSpace(parsed.Server) || string.IsNullOrWhiteSpace(parsed.Key)))
                    throw new InvalidOperationException("Silent first installation requires /server and /key.");
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
        private readonly bool _repair = InstallerEngine.ExistingInstallDetected;
        private readonly TextBox _server = new() { Width=430, PlaceholderText="http://server:8090" };
        private readonly TextBox _key = new() { Width=430, UseSystemPasswordChar=true, PlaceholderText="Organization enrollment key" };
        private readonly CheckBox _learning = new() { Text="Start device in Learning / Audit mode", Checked=true, AutoSize=true };
        private readonly Button _install = new() { AutoSize=true };
        private readonly Label _status = new() { AutoSize=true, MaximumSize=new Size(500,0) };

        public InstallForm(string? server,string? key,bool learning)
        {
            Text=$"AppControl Manager {Version} Installer"; Width=580; Height=390; StartPosition=FormStartPosition.CenterScreen; MaximizeBox=false;
            _server.Text=server ?? ""; _key.Text=key ?? ""; _learning.Checked=learning;
            _server.Enabled=!_repair; _key.Enabled=!_repair; _learning.Enabled=!_repair;
            _install.Text=_repair ? "Repair and Update AppControl Manager" : "Install AppControl Manager";
            var panel=new FlowLayoutPanel { Dock=DockStyle.Fill, FlowDirection=FlowDirection.TopDown, WrapContents=false, Padding=new Padding(24), AutoScroll=true };
            panel.Controls.Add(new Label { Text="AppControl Manager", Font=new Font("Segoe UI",18,FontStyle.Bold), AutoSize=true });
            panel.Controls.Add(new Label {
                Text=_repair
                    ? "Update this endpoint while preserving its existing enrollment and policy data."
                    : "Install and enroll this Windows endpoint.",
                AutoSize=true, Margin=new Padding(0,0,0,12)
            });
            panel.Controls.Add(new Label { Text="Server URL", AutoSize=true }); panel.Controls.Add(_server);
            panel.Controls.Add(new Label { Text="Enrollment key", AutoSize=true, Margin=new Padding(0,10,0,0) }); panel.Controls.Add(_key);
            panel.Controls.Add(_learning); panel.Controls.Add(_install); panel.Controls.Add(_status);
            Controls.Add(panel);
            _install.Click += async (_,__) => await InstallClicked();
        }

        private async Task InstallClicked()
        {
            _install.Enabled=false; _status.Text=_repair ? "Starting in-place repair..." : "Starting installation...";
            try
            {
                var progress=new Progress<string>(m=>_status.Text=m);
                await InstallerEngine.InstallAsync(_server.Text,_key.Text,_learning.Checked,progress,CancellationToken.None);
                _status.Text=_repair
                    ? "Update completed successfully. Existing enrollment and policy data were preserved."
                    : "Installation completed successfully. This device is enrolled and the AppControl Manager Agent is running.";
                MessageBox.Show(this,
                    _repair ? "AppControl Manager was repaired and updated successfully." : "AppControl Manager was installed successfully.",
                    _repair ? "Update Complete" : "Installation Complete",MessageBoxButtons.OK,MessageBoxIcon.Information);
                Close();
            }
            catch(Exception ex)
            {
                _status.Text=(_repair ? "Update failed: " : "Installation failed: ")+ex.Message;
                MessageBox.Show(this,ex.Message,_repair ? "Update Failed" : "Installation Failed",MessageBoxButtons.OK,MessageBoxIcon.Error);
                _install.Enabled=true;
            }
        }
    }

    private static class InstallerEngine
    {
        private static readonly string ProgramDataRoot=@"C:\ProgramData\AppControlManager";
        private static readonly string ProgramFilesRoot=@"C:\Program Files\AppControlManager";
        private static readonly string ConfigPath=Path.Combine(ProgramDataRoot,"config.json");
        private static readonly string UpdateRoot=Path.Combine(ProgramDataRoot,"Updates");
        private static readonly string UpdateStatusPath=Path.Combine(UpdateRoot,"update-status.json");
        private static readonly string UpdateCurrentPath=Path.Combine(UpdateRoot,"current-update.json");
        public static bool ExistingInstallDetected => File.Exists(ConfigPath);
        private sealed class EnrollResponse { public string device_id { get; set; }=""; public string device_key { get; set; }=""; }
        private sealed record ProcessResult(int ExitCode,string Stdout,string Stderr);

        public static async Task InstallAsync(string? server,string? key,bool startLearning,IProgress<string>? progress,CancellationToken ct)
        {
            var repair=ExistingInstallDetected;
            server=(server??"").Trim().TrimEnd('/'); key=(key??"").Trim();
            if(!repair)
            {
                if (!Uri.TryCreate(server,UriKind.Absolute,out var serverUri) || (serverUri.Scheme!="http" && serverUri.Scheme!="https")) throw new InvalidOperationException("Enter a valid AppControl Manager server URL.");
                if (key.Length<8) throw new InvalidOperationException("Enter a valid organization enrollment key.");
            }

            var temp=CreateSecureStagingDirectory();
            try
            {
                progress?.Report("Extracting embedded agent payload...");
                var zip=Path.Combine(temp,"agent-payload.zip");
                await using(var src=Assembly.GetExecutingAssembly().GetManifestResourceStream("AgentPayload") ?? throw new InvalidOperationException("Embedded agent payload is missing."))
                await using(var dst=File.Create(zip)) await src.CopyToAsync(dst,ct);
                var payload=Path.Combine(temp,"payload"); ZipFile.ExtractToDirectory(zip,payload,true);
                ValidatePayload(payload,repair);

                if(repair) await RepairExistingAsync(payload,progress,ct);
                else await InstallNewAsync(payload,server,key,startLearning,progress,ct);
            }
            finally { try { Directory.Delete(temp,true); } catch { } }
        }

        private static async Task RepairExistingAsync(string payload,IProgress<string>? progress,CancellationToken ct)
        {
            await Task.CompletedTask;
            ct.ThrowIfCancellationRequested();
            var currentVersion=GetInstalledVersion();
            var previousPreauthPolicy=ReadCurrentPreauthPolicy();
            string? preauthPolicy=null;
            string backup;
            try
            {
                progress?.Report("Pre-authorizing the signed repair payload for the current Windows App Control policy...");
                preauthPolicy=PreauthorizeRepairPayload(payload);
                ValidatePayload(payload,true);
                WriteInstallerUpdateStatus("staged",$"AppControl Manager {Version} repair payload verified and staged.",currentVersion,preauthPolicy,previousPreauthPolicy);

                progress?.Report("Preserving the current installation and existing enrollment and policy data...");
                backup=BackupExistingInstall();
            }
            catch(Exception preparationError)
            {
                if(!string.IsNullOrWhiteSpace(preauthPolicy) && TryRemovePreauthorization(preauthPolicy)) preauthPolicy=null;
                TryWriteInstallerUpdateStatus("failed",$"AppControl Manager {Version} repair preparation failed before services were stopped: {preparationError.Message}",currentVersion,preauthPolicy,previousPreauthPolicy);
                throw;
            }

            try
            {
                progress?.Report("Stopping the current agent and installing the repaired files...");
                StopInstalledProcesses();
                progress?.Report("Installing the repaired service, tray application and update helpers...");
                InstallPayloadFiles(payload);
                EnsureMainService();
                RegisterTrayStartup();
                StartMainAndVerify();
                TryStartTray();
                WriteInstallerUpdateStatus("installed",$"AppControl Manager agent {Version} installed successfully by the repair installer.",currentVersion,preauthPolicy,previousPreauthPolicy);
            }
            catch(Exception updateError)
            {
                try
                {
                    StopInstalledProcesses();
                    RestoreExistingInstall(backup);
                    EnsureMainService();
                    StartMainAndVerify();
                    TryStartTray();
                    WriteInstallerUpdateStatus("rolled_back",$"Installer repair to {Version} failed and AppControl Manager {currentVersion} was restored: {updateError.Message}",currentVersion,preauthPolicy,previousPreauthPolicy);
                }
                catch(Exception rollbackError)
                {
                    TryWriteInstallerUpdateStatus("failed",$"Installer repair to {Version} failed and rollback also failed: {updateError.Message} / {rollbackError.Message}",currentVersion,preauthPolicy,previousPreauthPolicy);
                    throw new InvalidOperationException($"The update failed and the previous installation could not be restored: {updateError.Message} / {rollbackError.Message}",updateError);
                }
                throw new InvalidOperationException($"The update failed; the previous AppControl Manager installation was restored: {updateError.Message}",updateError);
            }
        }

        private static async Task InstallNewAsync(string payload,string server,string key,bool startLearning,IProgress<string>? progress,CancellationToken ct)
        {
            progress?.Report("Enrolling this device...");
            using var http=new HttpClient { Timeout=TimeSpan.FromSeconds(60) };
            var body=new { hostname=Environment.MachineName, os_version=Environment.OSVersion.Version.ToString(), enrollment_token=key };
            var resp=await http.PostAsJsonAsync(server+"/api/enroll",body,ct);
            if(!resp.IsSuccessStatusCode) throw new InvalidOperationException($"Enrollment failed: HTTP {(int)resp.StatusCode} {await resp.Content.ReadAsStringAsync(ct)}");
            var enrolled=await resp.Content.ReadFromJsonAsync<EnrollResponse>(cancellationToken:ct) ?? throw new InvalidOperationException("Enrollment response was empty.");

            progress?.Report("Installing service, tray application and policy helpers...");
            PrepareDirectories();
            File.WriteAllText(ConfigPath,JsonSerializer.Serialize(new { server_url=server, device_id=enrolled.device_id, device_key=enrolled.device_key },new JsonSerializerOptions{WriteIndented=true}));
            InstallPayloadFiles(payload);
            EnsureMainService();
            RegisterTrayStartup();

            if(startLearning)
            {
                progress?.Report("Enabling Windows App Control Learning / Audit mode...");
                Run("powershell.exe",$"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{Path.Combine(ProgramFilesRoot,"Scripts","Start-LearningMode.ps1")}\" -NoTaskControl",timeoutMs:180000);
            }
            progress?.Report("Starting AppControl Manager services...");
            StartMainAndVerify();
            TryStartTray();
        }

        private static void PrepareDirectories()
        {
            Directory.CreateDirectory(ProgramDataRoot);
            Directory.CreateDirectory(ProgramFilesRoot);
            Directory.CreateDirectory(Path.Combine(ProgramFilesRoot,"Scripts"));
            Directory.CreateDirectory(Path.Combine(ProgramDataRoot,"Policies"));
            Directory.CreateDirectory(Path.Combine(ProgramDataRoot,"RuleWorker"));
            SecureRuleWorkerDirectory();
            Directory.CreateDirectory(Path.Combine(ProgramDataRoot,"RuleWorker","Jobs"));
        }

        private static string CreateSecureStagingDirectory()
        {
            var stagingRoot=Path.Combine(UpdateRoot,"InstallerStaging");
            Directory.CreateDirectory(stagingRoot);
            Run("icacls.exe",$"\"{stagingRoot}\" /inheritance:r");
            Run("icacls.exe",$"\"{stagingRoot}\" /grant:r \"*S-1-5-18:(OI)(CI)(F)\"");
            Run("icacls.exe",$"\"{stagingRoot}\" /grant:r \"*S-1-5-32-544:(OI)(CI)(F)\"");
            var staging=Path.Combine(stagingRoot,Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(staging);
            return staging;
        }

        private static void InstallPayloadFiles(string payload)
        {
            PrepareDirectories();
            File.Copy(Path.Combine(payload,"Service","AppControlManager.Service.exe"),Path.Combine(ProgramFilesRoot,"AppControlManager.Service.exe"),true);
            File.Copy(Path.Combine(payload,"Tray","AppControlManager.Tray.exe"),Path.Combine(ProgramFilesRoot,"AppControlManager.Tray.exe"),true);
            foreach(var script in Directory.EnumerateFiles(Path.Combine(payload,"scripts"),"*.ps1"))
            {
                File.Copy(script,Path.Combine(ProgramFilesRoot,"Scripts",Path.GetFileName(script)),true);
                File.Copy(script,Path.Combine(ProgramDataRoot,Path.GetFileName(script)),true);
            }
        }

        private static void SecureRuleWorkerDirectory()
        {
            var root=Path.Combine(ProgramDataRoot,"RuleWorker");
            Run("icacls.exe",$"\"{root}\" /inheritance:r");
            Run("icacls.exe",$"\"{root}\" /grant:r \"*S-1-5-18:(OI)(CI)(F)\"");
            Run("icacls.exe",$"\"{root}\" /grant:r \"*S-1-5-32-544:(OI)(CI)(F)\"");
            Run("icacls.exe",$"\"{root}\" /grant:r \"*S-1-5-19:(OI)(CI)(M)\"");
        }

        private static void EnsureMainService()
        {
            if(!ServiceExists("AppControlManager"))
                Run("sc.exe",$"create AppControlManager binPath= \"{Path.Combine(ProgramFilesRoot,"AppControlManager.Service.exe")}\" start= auto DisplayName= \"AppControl Manager Agent\"");
            Run("sc.exe","description AppControlManager \"AppControl Manager application-control agent\"");
        }

        private static void RegisterTrayStartup()
        {
            using var run=Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",true);
            run?.SetValue("AppControlManagerTray",$"\"{Path.Combine(ProgramFilesRoot,"AppControlManager.Tray.exe")}\"");
        }

        private static void StopInstalledProcesses()
        {
            foreach(var tray in Process.GetProcessesByName("AppControlManager.Tray"))
                try { tray.Kill(true); tray.WaitForExit(10000); } catch { }
            TryStopService("AppControlManagerRuleWorker");
            TryStopService("AppControlManager");
        }

        private static void TryStopService(string name)
        {
            if(!ServiceExists(name)) return;
            var result=RunProcess("sc.exe",$"stop {name}");
            if(result.ExitCode!=0 && result.ExitCode!=1062)
                throw new InvalidOperationException($"Could not stop {name}: {result.Stderr} {result.Stdout}".Trim());
            WaitForServiceStopped(name,30);
        }

        private static void StartMainAndVerify()
        {
            var start=RunProcess("sc.exe","start AppControlManager");
            if(start.ExitCode!=0 && start.ExitCode!=1056)
                throw new InvalidOperationException($"Could not start AppControlManager: {start.Stderr} {start.Stdout}".Trim());
            WaitForServiceRunning("AppControlManager",35);
            WaitForServiceRunning("AppControlManagerRuleWorker",30);
            WaitForServiceStable("AppControlManager",8);
            WaitForServiceStable("AppControlManagerRuleWorker",8);
        }

        private static void WaitForServiceRunning(string name,int seconds)
        {
            var deadline=DateTime.UtcNow.AddSeconds(seconds);
            do
            {
                var query=RunProcess("sc.exe",$"query {name}");
                if(query.ExitCode==0 && query.Stdout.Contains("RUNNING",StringComparison.OrdinalIgnoreCase)) return;
                Thread.Sleep(1000);
            } while(DateTime.UtcNow<deadline);
            var last=RunProcess("sc.exe",$"query {name}");
            throw new InvalidOperationException($"{name} did not reach Running state: exit={last.ExitCode} {last.Stderr} {last.Stdout}".Trim());
        }

        private static void WaitForServiceStable(string name,int seconds)
        {
            Thread.Sleep(TimeSpan.FromSeconds(seconds));
            var query=RunProcess("sc.exe",$"query {name}");
            if(query.ExitCode!=0 || !query.Stdout.Contains("RUNNING",StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"{name} did not remain running: exit={query.ExitCode} {query.Stderr} {query.Stdout}".Trim());
        }

        private static void WaitForServiceStopped(string name,int seconds)
        {
            var deadline=DateTime.UtcNow.AddSeconds(seconds);
            do
            {
                var query=RunProcess("sc.exe",$"query {name}");
                if(query.ExitCode!=0 || query.Stdout.Contains("STOPPED",StringComparison.OrdinalIgnoreCase)) return;
                Thread.Sleep(1000);
            } while(DateTime.UtcNow<deadline);
            throw new InvalidOperationException($"{name} did not stop within {seconds} seconds.");
        }

        private static bool ServiceExists(string name) => RunProcess("sc.exe",$"query {name}").ExitCode==0;

        private static string BackupExistingInstall()
        {
            var currentService=Path.Combine(ProgramFilesRoot,"AppControlManager.Service.exe");
            var currentTray=Path.Combine(ProgramFilesRoot,"AppControlManager.Tray.exe");
            if(!File.Exists(currentService) || !File.Exists(currentTray))
                throw new InvalidOperationException("The current AppControl Manager installation is incomplete and cannot be backed up safely.");

            var root=Path.Combine(UpdateRoot,"InstallerBackups");
            var backup=Path.Combine(root,$"pre-{Version}-{DateTime.UtcNow:yyyyMMdd-HHmmss}");
            Directory.CreateDirectory(backup);
            var saved=Path.Combine(backup,"AppControlManager");
            CopyDirectory(ProgramFilesRoot,saved);
            if(!File.Exists(Path.Combine(saved,"AppControlManager.Service.exe")) ||
               !File.Exists(Path.Combine(saved,"AppControlManager.Tray.exe")))
                throw new InvalidOperationException("The AppControl Manager rollback backup is incomplete.");
            return backup;
        }

        private static string? PreauthorizeRepairPayload(string payload)
        {
            var basePolicy=Path.Combine(ProgramDataRoot,"Policies","BasePolicy.xml");
            if(!File.Exists(basePolicy)) return null;

            var helper=Path.Combine(ProgramDataRoot,"New-SupplementalForFiles.ps1");
            if(!File.Exists(helper))
                throw new FileNotFoundException("The installed Windows App Control preauthorization helper is missing.",helper);

            var fileList=Path.Combine(Path.GetDirectoryName(payload)!,"installer-preauth-files.json");
            File.WriteAllText(fileList,JsonSerializer.Serialize(new[]{
                Path.Combine(payload,"Service","AppControlManager.Service.exe"),
                Path.Combine(payload,"Tray","AppControlManager.Tray.exe")
            }));
            var args=$"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{helper}\" -FileListPath \"{fileList}\" -Name \"AppControl Manager {Version} Installer Repair\" -AlreadyExpanded -Json";
            var result=RunProcess("powershell.exe",args,180000);
            if(result.ExitCode!=0)
                throw new InvalidOperationException($"Could not pre-authorize the {Version} repair payload: {result.Stderr} {result.Stdout}".Trim());

            foreach(var line in result.Stdout.Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries).Reverse())
            {
                var candidate=line.Trim();
                if(!candidate.StartsWith('{')) continue;
                try
                {
                    using var document=JsonDocument.Parse(candidate);
                    if(document.RootElement.TryGetProperty("policy_id",out var policyId) && !string.IsNullOrWhiteSpace(policyId.GetString()))
                        return policyId.GetString();
                }
                catch(JsonException) { }
            }
            throw new InvalidOperationException("The Windows App Control preauthorization helper did not return a policy ID.");
        }

        private static string GetInstalledVersion()
        {
            try
            {
                var raw=FileVersionInfo.GetVersionInfo(Path.Combine(ProgramFilesRoot,"AppControlManager.Service.exe")).FileVersion;
                if(System.Version.TryParse(raw,out var parsed))
                    return $"{parsed.Major}.{parsed.Minor}.{Math.Max(parsed.Build,0)}";
            }
            catch { }
            return "unknown";
        }

        private static string? ReadCurrentPreauthPolicy()
        {
            try
            {
                if(!File.Exists(UpdateCurrentPath)) return null;
                using var document=JsonDocument.Parse(File.ReadAllText(UpdateCurrentPath));
                return document.RootElement.TryGetProperty("preauth_policy_id",out var policyId) ? policyId.GetString() : null;
            }
            catch { return null; }
        }

        private static void WriteInstallerUpdateStatus(string status,string result,string fromVersion,string? preauthPolicy,string? previousPreauthPolicy)
        {
            Directory.CreateDirectory(UpdateRoot);
            var json=JsonSerializer.Serialize(new
            {
                status,
                target_version=Version,
                from_version=fromVersion,
                result,
                preauth_policy_id=preauthPolicy,
                previous_preauth_policy_id=previousPreauthPolicy,
                cleanup_complete=false,
                updated_at=DateTimeOffset.UtcNow.ToString("O")
            },new JsonSerializerOptions{WriteIndented=true});
            var temp=UpdateStatusPath+".tmp."+Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllText(temp,json);
                File.Move(temp,UpdateStatusPath,true);
            }
            catch
            {
                try { File.Delete(temp); } catch { }
                throw;
            }
        }

        private static bool TryWriteInstallerUpdateStatus(string status,string result,string fromVersion,string? preauthPolicy,string? previousPreauthPolicy)
        {
            try
            {
                WriteInstallerUpdateStatus(status,result,fromVersion,preauthPolicy,previousPreauthPolicy);
                return true;
            }
            catch(Exception ex)
            {
                AppendInstallerLog("Could not persist update status: "+ex);
                return false;
            }
        }

        private static bool TryRemovePreauthorization(string policyId)
        {
            try
            {
                Run("CiTool.exe",$"--remove-policy {policyId} -json");
                Run("CiTool.exe","--refresh -json");
                return true;
            }
            catch(Exception ex)
            {
                AppendInstallerLog("Could not remove temporary preauthorization policy "+policyId+": "+ex);
                return false;
            }
        }

        private static void AppendInstallerLog(string message)
        {
            try
            {
                Directory.CreateDirectory(ProgramDataRoot);
                File.AppendAllText(Path.Combine(ProgramDataRoot,"installer.log"),DateTimeOffset.Now+" "+message+Environment.NewLine);
            }
            catch { }
        }

        private static void RestoreExistingInstall(string backup)
        {
            var saved=Path.Combine(backup,"AppControlManager");
            if(!Directory.Exists(saved)) throw new InvalidOperationException("The installer backup does not contain the previous application files.");
            if(Directory.Exists(ProgramFilesRoot)) Directory.Delete(ProgramFilesRoot,true);
            CopyDirectory(saved,ProgramFilesRoot);
        }

        private static void CopyDirectory(string source,string destination)
        {
            Directory.CreateDirectory(destination);
            foreach(var file in Directory.EnumerateFiles(source)) File.Copy(file,Path.Combine(destination,Path.GetFileName(file)),true);
            foreach(var directory in Directory.EnumerateDirectories(source)) CopyDirectory(directory,Path.Combine(destination,Path.GetFileName(directory)));
        }

        private static void TryStartTray()
        {
            try { Process.Start(new ProcessStartInfo(Path.Combine(ProgramFilesRoot,"AppControlManager.Tray.exe")){UseShellExecute=true}); } catch { }
        }

        private static void ValidatePayload(string payload,bool requireSignedBinaries)
        {
            var manifestPath=Path.Combine(payload,"agent-manifest.json");
            if(!File.Exists(manifestPath)) throw new InvalidDataException("Installer payload manifest is missing.");
            using var document=JsonDocument.Parse(File.ReadAllText(manifestPath));
            var manifestVersion=document.RootElement.TryGetProperty("version",out var versionElement) ? versionElement.GetString() : null;
            if(!string.Equals(manifestVersion,Version,StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Installer payload version {manifestVersion} does not match installer version {Version}.");
            if(!document.RootElement.TryGetProperty("files",out var files) || files.ValueKind!=JsonValueKind.Array)
                throw new InvalidDataException("Installer payload manifest does not contain a files list.");

            var manifestPaths=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var payloadRoot=Path.GetFullPath(payload)+Path.DirectorySeparatorChar;
            foreach(var entry in files.EnumerateArray())
            {
                var relative=entry.TryGetProperty("path",out var pathElement) ? pathElement.GetString() : null;
                var expectedHash=entry.TryGetProperty("sha256",out var hashElement) ? hashElement.GetString() : null;
                if(string.IsNullOrWhiteSpace(relative) || string.IsNullOrWhiteSpace(expectedHash))
                    throw new InvalidDataException("Installer payload manifest contains an invalid file entry.");
                var manifestRelative=relative.Replace('\\','/');
                if(!manifestPaths.Add(manifestRelative))
                    throw new InvalidDataException("Installer payload manifest contains a duplicate file entry: "+relative);
                var normalized=relative.Replace('/',Path.DirectorySeparatorChar).Replace('\\',Path.DirectorySeparatorChar);
                var full=Path.GetFullPath(Path.Combine(payload,normalized));
                if(!full.StartsWith(payloadRoot,StringComparison.OrdinalIgnoreCase) || !File.Exists(full))
                    throw new InvalidDataException("Installer payload manifest references a missing or unsafe path: "+relative);
                using var stream=File.OpenRead(full);
                var actualHash=Convert.ToHexString(SHA256.HashData(stream));
                if(!actualHash.Equals(expectedHash.Replace("-",""),StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Installer payload file hash mismatch: "+relative);
                if(entry.TryGetProperty("size",out var sizeElement) && sizeElement.TryGetInt64(out var expectedSize) && new FileInfo(full).Length!=expectedSize)
                    throw new InvalidDataException("Installer payload file size mismatch: "+relative);
            }

            var requiredManifestPaths=new[]{
                "Service/AppControlManager.Service.exe",
                "Tray/AppControlManager.Tray.exe",
                "scripts/Start-LearningMode.ps1",
                "scripts/Apply-AgentUpdate.ps1"
            };
            foreach(var required in requiredManifestPaths)
                if(!manifestPaths.Contains(required)) throw new InvalidDataException("Installer payload manifest does not authenticate required file: "+required);
            foreach(var file in Directory.EnumerateFiles(payload,"*",SearchOption.AllDirectories))
            {
                var relative=Path.GetRelativePath(payload,file).Replace('\\','/');
                if(relative.Equals("agent-manifest.json",StringComparison.OrdinalIgnoreCase)) continue;
                if(!manifestPaths.Contains(relative)) throw new InvalidDataException("Installer payload contains an unmanifested file: "+relative);
            }
            if(requireSignedBinaries) VerifyPayloadSignatures(payload);
        }

        private static void VerifyPayloadSignatures(string payload)
        {
            var binaries=new[]{
                Path.Combine(payload,"Service","AppControlManager.Service.exe"),
                Path.Combine(payload,"Tray","AppControlManager.Tray.exe")
            };
            var literals=string.Join(",",binaries.Select(path=>"'"+path.Replace("'","''")+"'"));
            var command="$ErrorActionPreference='Stop';$files=@("+literals+");foreach($file in $files){$signature=Get-AuthenticodeSignature -LiteralPath $file;if($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate){throw \"Authenticode signature verification failed for $file. Status: $($signature.Status).\"}}";
            var result=RunProcess("powershell.exe",new[]{"-NoLogo","-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",command},120000);
            if(result.ExitCode!=0)
                throw new InvalidDataException($"Installer payload signature verification failed: {result.Stderr} {result.Stdout}".Trim());
        }

        private static void Run(string exe,string args,int timeoutMs=60000)
        {
            var result=RunProcess(exe,args,timeoutMs);
            if(result.ExitCode!=0) throw new InvalidOperationException($"{exe} failed ({result.ExitCode}): {result.Stderr} {result.Stdout}".Trim());
        }

        private static ProcessResult RunProcess(string exe,string args,int timeoutMs=60000)
        {
            return RunProcess(new ProcessStartInfo(exe,args),timeoutMs);
        }

        private static ProcessResult RunProcess(string exe,IEnumerable<string> args,int timeoutMs)
        {
            var startInfo=new ProcessStartInfo { FileName=exe };
            foreach(var arg in args) startInfo.ArgumentList.Add(arg);
            return RunProcess(startInfo,timeoutMs);
        }

        private static ProcessResult RunProcess(ProcessStartInfo startInfo,int timeoutMs)
        {
            startInfo.UseShellExecute=false;
            startInfo.RedirectStandardOutput=true;
            startInfo.RedirectStandardError=true;
            startInfo.CreateNoWindow=true;
            using var p=Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start "+startInfo.FileName);
            var stdout=p.StandardOutput.ReadToEndAsync();
            var stderr=p.StandardError.ReadToEndAsync();
            if(!p.WaitForExit(timeoutMs)){ try{p.Kill(true);}catch{} throw new TimeoutException(startInfo.FileName+" timed out."); }
            Task.WaitAll(stdout,stderr);
            return new ProcessResult(p.ExitCode,stdout.Result,stderr.Result);
        }
    }
}
