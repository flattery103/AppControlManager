using System.Text.Json;

namespace AppGuard.Core;

public sealed class JsonFileStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    public AgentConfig ReadConfig()
    {
        if (!File.Exists(AppGuardPaths.ConfigPath))
            throw new FileNotFoundException("Agent is not enrolled.", AppGuardPaths.ConfigPath);
        return JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(AppGuardPaths.ConfigPath), JsonOptions)
               ?? throw new InvalidDataException("Could not parse config.json");
    }

    public AgentState ReadState()
    {
        Directory.CreateDirectory(AppGuardPaths.ProgramDataRoot);
        using var mutex = new Mutex(false, @"Global\AppControlManager-State-v1");
        var locked = false;
        try
        {
            try { locked = mutex.WaitOne(TimeSpan.FromSeconds(15)); }
            catch (AbandonedMutexException) { locked = true; }
            if (!locked) throw new TimeoutException("Timed out waiting for AppControl Manager state lock.");
            if (!File.Exists(AppGuardPaths.StatePath)) return new AgentState();
            return JsonSerializer.Deserialize<AgentState>(File.ReadAllText(AppGuardPaths.StatePath), JsonOptions) ?? new AgentState();
        }
        finally { if (locked) mutex.ReleaseMutex(); }
    }

    public AgentState UpdateState(Action<AgentState> update)
    {
        Directory.CreateDirectory(AppGuardPaths.ProgramDataRoot);
        using var mutex = new Mutex(false, @"Global\AppControlManager-State-v1");
        var locked = false;
        try
        {
            try { locked = mutex.WaitOne(TimeSpan.FromSeconds(15)); }
            catch (AbandonedMutexException) { locked = true; }
            if (!locked) throw new TimeoutException("Timed out waiting for AppControl Manager state lock.");
            AgentState state;
            if (File.Exists(AppGuardPaths.StatePath))
                state = JsonSerializer.Deserialize<AgentState>(File.ReadAllText(AppGuardPaths.StatePath), JsonOptions) ?? new AgentState();
            else
                state = new AgentState();
            update(state);
            var temp = AppGuardPaths.StatePath + ".tmp." + Environment.ProcessId;
            File.WriteAllText(temp, JsonSerializer.Serialize(state, JsonOptions));
            File.Move(temp, AppGuardPaths.StatePath, true);
            return state;
        }
        finally { if (locked) mutex.ReleaseMutex(); }
    }
}
