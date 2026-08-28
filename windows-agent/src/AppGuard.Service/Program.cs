using AppGuard.Core;
using AppGuard.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

var ruleWorkerMode = args.Any(x => x.Equals("--rule-worker", StringComparison.OrdinalIgnoreCase));
var hostArgs = args.Where(x => !x.Equals("--rule-worker", StringComparison.OrdinalIgnoreCase)).ToArray();
var builder = Host.CreateApplicationBuilder(hostArgs);

if (ruleWorkerMode)
{
    builder.Services.AddWindowsService(options => options.ServiceName = "AppControl Manager Rule Worker");
    builder.Services.AddHostedService<RuleWorkerService>();
    await builder.Build().RunAsync();
    return;
}

Directory.CreateDirectory(AppGuardPaths.ProgramDataRoot);
Directory.CreateDirectory(AppGuardPaths.PolicyDirectory);
Directory.CreateDirectory(AppGuardPaths.BlockCacheDirectory);
Directory.CreateDirectory(AppGuardPaths.UpdateDirectory);

string? ruleWorkerProvisioningError = null;
try { RuleWorkerProvisioner.EnsureInstalled(); }
catch (Exception ex) { ruleWorkerProvisioningError = ex.Message; }

builder.Services.AddWindowsService(options => options.ServiceName = "AppControl Manager Agent");
builder.Services.AddSingleton<JsonFileStore>();
builder.Services.AddSingleton<FileLogger>();
builder.Services.AddSingleton<ApiClient>();
builder.Services.AddSingleton<EventCollector>();
builder.Services.AddSingleton<PolicyProgressTracker>();
builder.Services.AddSingleton<BackgroundPolicyStore>();
builder.Services.AddSingleton<RuleWorkerClient>();
builder.Services.AddSingleton<PolicyHelper>();
builder.Services.AddSingleton<InstallationModeStore>();
builder.Services.AddSingleton<InstallationModeManager>();
builder.Services.AddSingleton<BackgroundPolicyProcessor>();
builder.Services.AddSingleton<AgentUpdater>();
builder.Services.AddSingleton<BlockedFileCache>();
builder.Services.AddSingleton<LocalRequestServer>();
builder.Services.AddHostedService<AgentWorker>();
var host = builder.Build();
if (!string.IsNullOrWhiteSpace(ruleWorkerProvisioningError))
    host.Services.GetRequiredService<FileLogger>().Write("rule-worker provisioning failed: " + ruleWorkerProvisioningError);
await host.RunAsync();
