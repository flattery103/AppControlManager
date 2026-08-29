using System.Diagnostics.Eventing.Reader;
using AppGuard.Core;
using Microsoft.Extensions.Hosting;

namespace AppGuard.Service;

public sealed class LearningEventWatcher : BackgroundService
{
    private readonly LearningFileCache _cache;
    private readonly FileLogger _log;
    private EventLogWatcher? _watcher;

    public LearningEventWatcher(LearningFileCache cache, FileLogger log)
    {
        _cache = cache;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var query = new EventLogQuery("Microsoft-Windows-CodeIntegrity/Operational", PathType.LogName, "*[System[(EventID=3076)]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEvent;
            _watcher.Enabled = true;
            await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception ex) { _log.Write("learning-watcher: " + ex.Message); }
        finally
        {
            if (_watcher is not null)
            {
                _watcher.Enabled = false;
                _watcher.EventRecordWritten -= OnEvent;
                _watcher.Dispose();
            }
        }
    }

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord is null) return;
        try
        {
            using (e.EventRecord)
            {
                if (!PolicyInspector.GetMode().Equals("learning", StringComparison.OrdinalIgnoreCase)) return;
                _cache.Capture(EventCollector.FromRecord(e.EventRecord));
            }
        }
        catch (Exception ex) { _log.Write("learning-watcher event: " + ex.Message); }
    }
}
