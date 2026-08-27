using AppGuard.Core;

namespace AppGuard.Service;

public sealed class PolicyProgressTracker
{
    private readonly object _gate = new();
    private PolicyProgressInfo? _current;

    public void Update(long requestId, string phase, string message, int fileCount = 0)
    {
        lock (_gate)
        {
            _current = new PolicyProgressInfo
            {
                RequestId = requestId,
                Phase = phase,
                Message = message,
                FileCount = fileCount,
                UpdatedAt = DateTimeOffset.UtcNow.ToString("O")
            };
        }
    }

    public PolicyProgressInfo? Snapshot()
    {
        lock (_gate)
        {
            if (_current is null) return null;
            return new PolicyProgressInfo
            {
                RequestId = _current.RequestId,
                Phase = _current.Phase,
                Message = _current.Message,
                FileCount = _current.FileCount,
                UpdatedAt = _current.UpdatedAt
            };
        }
    }
}
