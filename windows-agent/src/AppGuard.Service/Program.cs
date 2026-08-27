using AppGuard.Core;
using AppGuard.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

Directory.CreateDirectory(AppGuardPaths.ProgramDataRoot);
Directory.CreateDirectory(AppGuardPaths.PolicyDirectory);
Directory.CreateDirectory(AppGuardPaths.BlockCacheDirectory);
Directory.CreateDirectory(AppGuardPaths.UpdateDirectory);

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "AppControl Manager Agent");
builder.Services.AddSingleton<JsonFileStore>();
builder.Services.AddSingleton<FileLogger>();
builder.Services.AddSingleton<ApiClient>();
builder.Services.AddSingleton<EventCollector>();
builder.Services.AddSingleton<PolicyProgressTracker>();
builder.Services.AddSingleton<PolicyHelper>();
builder.Services.AddSingleton<AgentUpdater>();
builder.Services.AddSingleton<BlockedFileCache>();
builder.Services.AddSingleton<LocalRequestServer>();
builder.Services.AddHostedService<AgentWorker>();
await builder.Build().RunAsync();
