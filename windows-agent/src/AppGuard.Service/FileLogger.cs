using AppGuard.Core;

namespace AppGuard.Service;

public sealed class FileLogger
{
    private readonly object _sync = new();
    public void Write(string message)
    {
        try
        {
            lock (_sync)
            {
                Directory.CreateDirectory(AppGuardPaths.ProgramDataRoot);
                File.AppendAllText(AppGuardPaths.ServiceLog, $"{DateTimeOffset.Now:O} {message}{Environment.NewLine}");
            }
        }
        catch { }
    }
}
