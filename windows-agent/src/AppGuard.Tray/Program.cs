using System.Diagnostics;

namespace AppGuard.Tray;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        using var instanceMutex = new Mutex(
            true,
            $@"Local\AppControlManager.Tray.Session.{Process.GetCurrentProcess().SessionId}",
            out var createdNew);
        if (!createdNew) return;

        ApplicationConfiguration.Initialize();
        SynchronizationContext.SetSynchronizationContext(new WindowsFormsSynchronizationContext());
        Application.Run(new TrayContext(SynchronizationContext.Current!));
    }
}
