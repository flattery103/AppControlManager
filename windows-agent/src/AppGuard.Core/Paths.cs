namespace AppGuard.Core;

public static class AppGuardPaths
{
    public const string ProgramDataRoot = @"C:\ProgramData\AppControlManager";
    public const string ProgramFilesRoot = @"C:\Program Files\AppControlManager";
    public static string ConfigPath => Path.Combine(ProgramDataRoot, "config.json");
    public static string StatePath => Path.Combine(ProgramDataRoot, "state.json");
    public static string PolicyDirectory => Path.Combine(ProgramDataRoot, "Policies");
    public static string BasePolicyXml => Path.Combine(PolicyDirectory, "BasePolicy.xml");
    public static string ServiceLog => Path.Combine(ProgramDataRoot, "agent-service.log");
    public static string BlockCacheDirectory => Path.Combine(ProgramDataRoot, "BlockedCache");
    public static string ScriptsDirectory => Path.Combine(ProgramFilesRoot, "Scripts");
    public static string UpdateDirectory => Path.Combine(ProgramDataRoot, "Updates");
    public static string UpdateStatusPath => Path.Combine(UpdateDirectory, "update-status.json");
    public static string UpdateCurrentPath => Path.Combine(UpdateDirectory, "current-update.json");
    public static string BackgroundPolicyQueuePath => Path.Combine(ProgramDataRoot, "background-policy-state.json");
    public static string RuleFragmentDirectory => Path.Combine(ProgramDataRoot, "RuleFragments");
    public static string RuleWorkerDirectory => Path.Combine(ProgramDataRoot, "RuleWorker");
    public static string RuleWorkerJobsDirectory => Path.Combine(RuleWorkerDirectory, "Jobs");
    public static string RuleWorkerLog => Path.Combine(RuleWorkerDirectory, "rule-worker.log");
    public static string LearnedApplicationsPath => Path.Combine(ProgramDataRoot, "learned.json");
    public static string InstallationModeStatePath => Path.Combine(ProgramDataRoot, "installation-mode.json");
    public const string PipeName = "AppControlManager.Requests";
}
