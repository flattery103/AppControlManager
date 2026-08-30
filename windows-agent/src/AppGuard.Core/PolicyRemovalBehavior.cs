namespace AppGuard.Core;

public static class PolicyRemovalBehavior
{
    public const int PolicyNotFoundExitCode = unchecked((int)0x80070002);

    public static bool IsAlreadyAbsent(int exitCode, string? standardOutput, string? standardError)
    {
        if (exitCode == PolicyNotFoundExitCode) return true;
        var combined = (standardOutput ?? string.Empty) + " " + (standardError ?? string.Empty);
        return combined.Contains("\"OperationResult\":-2147024894", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("\"OperationResult\": -2147024894", StringComparison.OrdinalIgnoreCase);
    }
}
