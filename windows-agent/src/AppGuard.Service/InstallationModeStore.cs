using System.Text.Json;
using AppGuard.Core;

namespace AppGuard.Service;

public sealed class InstallationModeStore
{
    private static readonly Mutex Gate = new(false, @"Global\AppControlManager.InstallationModeState");
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public InstallationModeState Read()
    {
        Gate.WaitOne();
        try
        {
            if (!File.Exists(AppGuardPaths.InstallationModeStatePath)) return new InstallationModeState();
            try { return JsonSerializer.Deserialize<InstallationModeState>(File.ReadAllText(AppGuardPaths.InstallationModeStatePath), Json) ?? new InstallationModeState(); }
            catch { return new InstallationModeState(); }
        }
        finally { Gate.ReleaseMutex(); }
    }

    public void Write(InstallationModeState state)
    {
        Gate.WaitOne();
        try
        {
            Directory.CreateDirectory(AppGuardPaths.ProgramDataRoot);
            var tmp = AppGuardPaths.InstallationModeStatePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(state, Json));
            File.Move(tmp, AppGuardPaths.InstallationModeStatePath, true);
        }
        finally { Gate.ReleaseMutex(); }
    }
}
